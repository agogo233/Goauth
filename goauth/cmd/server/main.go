package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zitadel/oidc/v3/pkg/op"

	"goauth/internal/config"
	"goauth/internal/db"
	"goauth/internal/handler"
	"goauth/internal/middleware"
	"goauth/internal/model"
	"goauth/internal/oidc"
	"goauth/internal/repo"
	"goauth/internal/service"
	"goauth/internal/util"
)

var version = "dev"

var (
	configPath string
)

var rootCmd = &cobra.Command{
	Use:     "goauth",
	Short:   "Goauth - Lightweight OIDC Provider",
	Version: version,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the server",
	Run:   runServe,
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
	Run:   runMigrate,
}

var resetPasswordCmd = &cobra.Command{
	Use:   "reset-password",
	Short: "Reset a user's password",
	Run:   runResetPassword,
}

var createAdminCmd = &cobra.Command{
	Use:   "create-admin",
	Short: "Create an admin user",
	Run:   runCreateAdmin,
}

var (
	resetUsername string
)

var (
	adminUsername string
	adminPassword string
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "Path to config file")

	serveCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to config file")

	migrateCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to config file")

	resetPasswordCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to config file")
	resetPasswordCmd.Flags().StringVarP(&resetUsername, "username", "u", "", "Username to reset password for")
	resetPasswordCmd.MarkFlagRequired("username")

	createAdminCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to config file")
	createAdminCmd.Flags().StringVarP(&adminUsername, "username", "u", "", "Admin username")
	createAdminCmd.Flags().StringVarP(&adminPassword, "password", "p", "", "Admin password")
	createAdminCmd.MarkFlagRequired("username")
	createAdminCmd.MarkFlagRequired("password")

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(migrateCmd)
	rootCmd.AddCommand(resetPasswordCmd)
	rootCmd.AddCommand(createAdminCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runServe(cmd *cobra.Command, args []string) {
	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Setup logging
	setupLogging(cfg.Logging.Level)

	// Connect to database
	database, err := db.New(&cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	defer database.Close()

	// Run migrations
	if err := database.RunMigrations(); err != nil {
		log.Fatal().Err(err).Msg("Failed to run migrations")
	}

	// Setup Gin
	if cfg.Server.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Setup repositories
	userRepo := repo.NewUserRepo(database.DB)
	groupRepo := repo.NewGroupRepo(database.DB)
	sessionRepo := repo.NewSessionRepo(database.DB)
	keyRepo := repo.NewKeyRepo(database.DB)
	oidcRepo := repo.NewOIDCRepo(database.DB)
	invitationRepo := repo.NewInvitationRepo(database.DB)
	proxyAuthRepo := repo.NewProxyAuthRepo(database.DB)
	clientRepo := repo.NewClientRepo(database.DB)

	// Setup OIDC
	storage, err := oidc.NewStorage(userRepo, groupRepo, keyRepo, oidcRepo, clientRepo, sessionRepo, cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create OIDC storage")
	}

	provider, err := oidc.NewProvider(cfg, storage)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create OIDC provider")
	}

	// Setup services
	protector := util.NewBruteForceProtector(database.DB, cfg.Security.LoginMaxAttempts, cfg.Security.LoginBlockDuration)
	totpService := service.NewTotpService(database.DB, cfg)
	invitationService := service.NewInvitationService(invitationRepo, groupRepo, database.DB)
	authService := service.NewAuthService(userRepo, sessionRepo, groupRepo, totpService, invitationService, protector, cfg)
	userService := service.NewUserService(userRepo, sessionRepo, groupRepo, database.DB, cfg)
	groupService := service.NewGroupService(groupRepo, database.DB)
	auditService := service.NewAuditService(database.DB)

	// Setup handlers
	healthHandler := handler.NewHealthHandler()
	publicHandler := handler.NewPublicHandler(cfg)
	authHandler := handler.NewAuthHandler(authService, userService, auditService, cfg)
	userHandler := handler.NewUserHandler(userService, totpService, sessionRepo, cfg)
	adminHandler := handler.NewAdminHandler(userService, groupService, auditService, invitationService, totpService, userRepo, groupRepo, clientRepo, invitationRepo, proxyAuthRepo)
	oidcHandler := handler.NewOIDCHandler(provider)
	proxyAuthHandler := handler.NewProxyAuthHandler(authService, proxyAuthRepo, groupRepo, sessionRepo)

	// Setup middleware
	authMiddleware := middleware.NewAuthMiddleware(authService, cfg)
	// Rate limiting - configurable via environment variable (0 = disabled)
	rateLimitPerMin := 100 // default 100 req/min
	if envRate := os.Getenv("APP_SERVER_RATELIMIT"); envRate != "" {
		fmt.Sscanf(envRate, "%d", &rateLimitPerMin)
	}
	var rateLimiter *middleware.RateLimiter
	if rateLimitPerMin > 0 {
		rateLimiter = middleware.NewRateLimiter(rateLimitPerMin, time.Minute)
	}

	router := setupRouter(cfg, database.DB, healthHandler, publicHandler, authHandler, userHandler, adminHandler, oidcHandler, proxyAuthHandler, authMiddleware, rateLimiter, provider, authService)

	// Create server
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server
	go func() {
		log.Info().
			Str("addr", srv.Addr).
			Str("environment", cfg.Server.Environment).
			Str("issuer", cfg.OIDC.Issuer).
			Msg("Server starting")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Server failed")
		}
	}()

	// Start background cleanup tasks
	ctx, cancelCleanup := context.WithCancel(context.Background())
	go runCleanupTasks(ctx, database.DB, protector, auditService, cfg)

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Stop cleanup tasks
	cancelCleanup()

	// Stop rate limiter cleanup goroutine
	if rateLimiter != nil {
		rateLimiter.Stop()
	}

	log.Info().Msg("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	log.Info().Msg("Server exited")
}

func runMigrate(cmd *cobra.Command, args []string) {
	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Setup logging
	setupLogging(cfg.Logging.Level)

	// Connect to database
	database, err := db.New(&cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	defer database.Close()

	// Run migrations
	if err := database.RunMigrations(); err != nil {
		log.Fatal().Err(err).Msg("Failed to run migrations")
	}

	log.Info().Msg("Migrations completed successfully")
}

func runResetPassword(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Setup logging
	setupLogging(cfg.Logging.Level)

	// Connect to database
	database, err := db.New(&cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	defer database.Close()

	// Setup repository
	userRepo := repo.NewUserRepo(database.DB)

	// Find user
	user, err := userRepo.FindByUsername(ctx, resetUsername)
	if err != nil {
		log.Fatal().Err(err).Str("username", resetUsername).Msg("User not found")
	}

	// Generate random password
	newPassword, err := util.GenerateRandomPassword(16)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to generate random password")
	}

	// Hash password
	hashedPassword, err := util.HashPassword(newPassword)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to hash password")
	}

	// Update password
	user.PasswordHash = &hashedPassword
	if err := userRepo.Update(ctx, user); err != nil {
		log.Fatal().Err(err).Msg("Failed to update password")
	}

	fmt.Printf("Password reset for user '%s'\n", resetUsername)
	fmt.Printf("New password: %s\n", newPassword)
	log.Info().Str("username", resetUsername).Msg("Password reset successfully")
}

func runCreateAdmin(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Setup logging
	setupLogging(cfg.Logging.Level)

	// Connect to database
	database, err := db.New(&cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	defer database.Close()

	// Setup repository
	userRepo := repo.NewUserRepo(database.DB)

	// Check if user already exists
	existingUser, _ := userRepo.FindByUsername(ctx, adminUsername)
	if existingUser != nil {
		log.Fatal().Str("username", adminUsername).Msg("User already exists")
	}

	// Validate password strength (min length: 8, min score: 3)
	if err := util.CheckPasswordStrength(adminPassword, 8, 3); err != nil {
		log.Fatal().Err(err).Msg("Password validation failed")
	}

	// Hash password
	hashedPassword, err := util.HashPassword(adminPassword)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to hash password")
	}

	// Create admin user
	user := &model.User{
		ID:            uuid.NewString(),
		Username:      adminUsername,
		PasswordHash:  &hashedPassword,
		IsAdmin:       true,
		Approved:      true,
		EmailVerified: true,
	}

	if err := userRepo.Create(ctx, user); err != nil {
		log.Fatal().Err(err).Msg("Failed to create admin user")
	}

	fmt.Printf("Admin user '%s' created successfully\n", adminUsername)
	log.Info().Str("username", adminUsername).Msg("Admin user created")
}

func setupLogging(level string) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	switch level {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

func setupRouter(
	cfg *config.Config,
	db *sqlx.DB,
	healthHandler *handler.HealthHandler,
	publicHandler *handler.PublicHandler,
	authHandler *handler.AuthHandler,
	userHandler *handler.UserHandler,
	adminHandler *handler.AdminHandler,
	oidcHandler *handler.OIDCHandler,
	proxyAuthHandler *handler.ProxyAuthHandler,
	authMiddleware *middleware.AuthMiddleware,
	rateLimiter *middleware.RateLimiter,
	provider *oidc.Provider,
	authService *service.AuthService,
) *gin.Engine {
	router := gin.New()

	// Global middleware
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	// 安全响应头
	router.Use(middleware.SecurityHeaders())

	// CORS - 使用配置化允许的来源
	corsOrigins := cfg.Server.CORSAllowOrigins
	// 开发环境默认允许所有来源
	if len(corsOrigins) == 0 && cfg.Server.Environment == "development" {
		corsOrigins = []string{"*"}
	}
	router.Use(middleware.CORS(corsOrigins))

	// Health check (no rate limiting)
	router.GET("/health", healthHandler.Health)
	router.GET("/ready", healthHandler.Ready)

	// Serve static files (no rate limiting - allows login page to always load)
	router.Static("/css", "./web/css")
	router.Static("/js", "./web/js")
	router.Static("/assets", "./web/assets")

	// Inject nonce into index.html for CSP
	injectNonce := func(c *gin.Context) {
		nonceVal, exists := c.Get(middleware.CSPNonceKey)
		nonce := ""
		if exists {
			nonce, _ = nonceVal.(string)
		}
		indexHTML, err := os.ReadFile("./web/index.html")
		if err != nil {
			c.String(http.StatusInternalServerError, "Internal Server Error")
			return
		}
		content := strings.ReplaceAll(string(indexHTML), "__CSP_NONCE__", nonce)
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(content))
	}
	router.GET("/", injectNonce)
	router.GET("/invite/:token", injectNonce)

	// API routes
	api := router.Group("/api")
	{
		// Apply rate limiting only to API routes (not static files)
		if rateLimiter != nil {
			api.Use(middleware.RateLimit(rateLimiter))
		}

		// CSRF 保护（跳过登录、注册和登出端点）
		api.Use(middleware.CSRF(middleware.CSRFConfig{
			SkipPaths: []string{
				"/api/auth/login",
				"/api/auth/register",
				"/api/auth/logout",
				"/api/public/password-strength", // 公开API，不需要CSRF保护
			},
		}))

		// Public routes
		public := api.Group("/public")
		{
			public.GET("/config", publicHandler.GetConfig)
			public.POST("/password-strength", publicHandler.CheckPasswordStrength)
		}

		// Auth routes
		auth := api.Group("/auth")
		{
			auth.POST("/login", authHandler.Login)
			auth.POST("/register", authHandler.Register)
			auth.POST("/logout", authHandler.Logout)
			auth.POST("/totp", authHandler.TotpLogin)
		}

		// User routes (authenticated)
		user := api.Group("/user")
		user.Use(authMiddleware.RequireAuth())
		{
			user.GET("/me", userHandler.GetMe)
			user.PATCH("/profile", userHandler.UpdateProfile)
			user.PATCH("/password", userHandler.UpdatePassword)
			user.DELETE("/totp", userHandler.RemoveTotp)
			user.GET("/sessions", userHandler.GetSessions)
			user.DELETE("/sessions/:id", userHandler.TerminateSession)
			// TOTP 备用码
			user.GET("/totp/backup-codes", userHandler.GenerateBackupCodes)
			user.POST("/totp/verify-backup-code", userHandler.VerifyBackupCode)
		}

		// MFA setup routes (accessible by pwd-mfa-setup-required users)
		mfaSetup := api.Group("/mfa-setup")
		mfaSetup.Use(authMiddleware.RequireMfaSetup())
		{
			mfaSetup.GET("/me", userHandler.GetMe)
			mfaSetup.POST("/totp/setup", userHandler.SetupTotp)
			mfaSetup.POST("/totp/verify", userHandler.VerifyTotp)
		}

		// Admin routes
		admin := api.Group("/admin")
		admin.Use(authMiddleware.RequireAuth())
		admin.Use(authMiddleware.RequireAdmin())
		{
			// User management
			admin.GET("/users", adminHandler.ListUsers)
			admin.GET("/users/:id", adminHandler.GetUser)
			admin.PATCH("/users/:id", adminHandler.UpdateUser)
			admin.POST("/users/:id/approve", adminHandler.ApproveUser)
			admin.POST("/users/:id/disable", adminHandler.DisableUser)
			admin.POST("/users/:id/enable", adminHandler.EnableUser)
			admin.POST("/users/:id/reset-password", adminHandler.ResetUserPassword)
			admin.DELETE("/users/:id/totp", adminHandler.RemoveUserTotp)
			admin.DELETE("/users/:id", adminHandler.DeleteUser)
			admin.POST("/users/:id/admin", adminHandler.SetAdmin)

			// Group management
			admin.GET("/groups", adminHandler.ListGroups)
			admin.POST("/groups", adminHandler.CreateGroup)
			admin.PATCH("/groups/:id", adminHandler.UpdateGroup)
			admin.DELETE("/groups/:id", adminHandler.DeleteGroup)
			admin.GET("/groups/:id/members", adminHandler.GetGroupMembers)
			admin.POST("/groups/:id/members", adminHandler.AddGroupMember)
			admin.DELETE("/groups/:id/members/:userId", adminHandler.RemoveGroupMember)

			// Client management
			admin.GET("/clients", adminHandler.ListClients)
			admin.POST("/clients", adminHandler.CreateClient)
			admin.PATCH("/clients/:id", adminHandler.UpdateClient)
			admin.DELETE("/clients/:id", adminHandler.DeleteClient)

			// Invitation management
			admin.GET("/invitations", adminHandler.ListInvitations)
			admin.POST("/invitations", adminHandler.CreateInvitation)
			admin.DELETE("/invitations/:id", adminHandler.DeleteInvitation)

			// ProxyAuth management
			admin.GET("/proxy-auth", adminHandler.ListProxyAuth)
			admin.POST("/proxy-auth", adminHandler.CreateProxyAuth)
			admin.PATCH("/proxy-auth/:id", adminHandler.UpdateProxyAuth)
			admin.DELETE("/proxy-auth/:id", adminHandler.DeleteProxyAuth)

			// Audit logs
			admin.GET("/audit-logs", adminHandler.ListAuditLogs)
		}
	}

	// OIDC routes - handle all OIDC endpoints through the provider
	// 路径必须与 OIDC discovery 文档中的路径一致
	oidcRouter := router.Group("")
	{
		oidcRouter.GET("/.well-known/openid-configuration", oidcHandler.Handler())
		oidcRouter.GET("/keys", oidcHandler.JWKS)
		// Let OIDC provider handle authorize - it will redirect to Client.LoginURL
		oidcRouter.GET("/authorize", oidcHandler.Authorize)
		oidcRouter.POST("/authorize", oidcHandler.Authorize)
		// Token 端点使用 /oauth/token 以匹配 OIDC discovery 文档
		oidcRouter.POST("/oauth/token", oidcHandler.Token)
		oidcRouter.POST("/token", oidcHandler.Token) // 兼容旧路径
		oidcRouter.GET("/userinfo", oidcHandler.UserInfo)
		oidcRouter.POST("/userinfo", oidcHandler.UserInfo)
		oidcRouter.POST("/oauth/introspect", oidcHandler.Introspect)
		oidcRouter.POST("/introspect", oidcHandler.Introspect) // 兼容旧路径
		oidcRouter.POST("/revoke", oidcHandler.Revoke)
		oidcRouter.GET("/endsession", oidcHandler.EndSession)
		oidcRouter.POST("/endsession", oidcHandler.EndSession)
	}

	// OIDC interaction endpoint - for logged-in users to complete authorization
	router.GET("/interaction", func(c *gin.Context) {
		authRequestID := c.Query("authRequestID")
		if authRequestID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing authRequestID"})
			return
		}

		// Check if user is already logged in via session
		token, err := c.Cookie("session")
		if err == nil && token != "" {
			// Validate session
			user, err := authService.ValidateSession(c.Request.Context(), token)
			if err == nil && user != nil {
				// User is logged in, auto-complete the authorization
				if err := provider.Storage().CompleteAuthRequest(c.Request.Context(), authRequestID, user.ID); err != nil {
					log.Error().Err(err).Str("authRequestID", authRequestID).Msg("Failed to complete auth request")
					c.Redirect(http.StatusFound, "/#/login?authRequestID="+authRequestID+"&error=session_error")
					return
				}
				// Redirect to callback
				callbackURL := "/api/cb?id=" + authRequestID
				c.Redirect(http.StatusFound, callbackURL)
				return
			}
		}

		// User not logged in, redirect to login page with authRequestID
		c.Redirect(http.StatusFound, "/#/login?authRequestID="+authRequestID)
	})

	// OIDC callback endpoint - handles the final redirect to client
	router.Any("/api/cb", func(c *gin.Context) {
		// Check for error response
		if err := c.Query("error"); err != "" {
			c.Redirect(http.StatusFound, "/#/login?error="+c.Query("error_description"))
			return
		}

		// Use the standard callback handler from OIDC library
		// This will validate the auth request and redirect to client's redirect_uri
		op.AuthorizeCallbackHandler(provider.OpProvider())(c.Writer, c.Request)
	})

	// ProxyAuth routes (for Traefik/Nginx)
	router.GET("/authz/forward-auth", proxyAuthHandler.ForwardAuth)
	router.GET("/authz/auth-request", proxyAuthHandler.AuthRequest)

	return router
}

// runCleanupTasks 后台定时清理任务
func runCleanupTasks(
	ctx context.Context,
	db *sqlx.DB,
	protector *util.BruteForceProtector,
	auditService *service.AuditService,
	cfg *config.Config,
) {
	// 清理间隔默认 24 小时
	cleanupInterval := time.Duration(cfg.Security.LoginAttemptCleanup) * time.Hour
	if cleanupInterval <= 0 {
		cleanupInterval = 24 * time.Hour
	}

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	// 启动时先执行一次清理
	doCleanup(ctx, db, protector, auditService, cfg)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Cleanup tasks stopped")
			return
		case <-ticker.C:
			doCleanup(ctx, db, protector, auditService, cfg)
		}
	}
}

// doCleanup 执行清理操作
func doCleanup(
	ctx context.Context,
	db *sqlx.DB,
	protector *util.BruteForceProtector,
	auditService *service.AuditService,
	cfg *config.Config,
) {
	// 清理旧的登录尝试记录（保留与封锁时长相同的记录，额外的保留 7 天）
	retentionDays := cfg.Security.LoginBlockDuration/1440 + 7 // 分钟转天数 + 7 天缓冲
	if retentionDays < 7 {
		retentionDays = 7
	}

	if err := protector.CleanupOldAttempts(ctx, retentionDays); err != nil {
		log.Error().Err(err).Msg("Failed to cleanup old login attempts")
	} else {
		log.Debug().Int("retention_days", retentionDays).Msg("Cleaned up old login attempts")
	}

	// 清理旧的审计日志
	if cfg.Security.AuditLogRetention > 0 {
		deleted, err := auditService.CleanupOldLogs(ctx, cfg.Security.AuditLogRetention)
		if err != nil {
			log.Error().Err(err).Msg("Failed to cleanup old audit logs")
		} else if deleted > 0 {
			log.Info().Int64("deleted", deleted).Int("retention_days", cfg.Security.AuditLogRetention).Msg("Cleaned up old audit logs")
		}
	}

	// 清理过期的 OIDC payloads
	result, err := db.ExecContext(ctx, `DELETE FROM oidc_payloads WHERE expiresAt IS NOT NULL AND expiresAt < ?`, time.Now())
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup expired OIDC payloads")
	} else if rows, _ := result.RowsAffected(); rows > 0 {
		log.Debug().Int64("deleted", rows).Msg("Cleaned up expired OIDC payloads")
	}

	// 清理过期的密钥
	result, err = db.ExecContext(ctx, `DELETE FROM keys WHERE expiresAt < ?`, time.Now())
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup expired keys")
	} else if rows, _ := result.RowsAffected(); rows > 0 {
		log.Debug().Int64("deleted", rows).Msg("Cleaned up expired keys")
	}

	// 清理过期的邀请
	result, err = db.ExecContext(ctx, `DELETE FROM invitations WHERE expiresAt < ?`, time.Now())
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup expired invitations")
	} else if rows, _ := result.RowsAffected(); rows > 0 {
		log.Info().Int64("deleted", rows).Msg("Cleaned up expired invitations")
	}

	// 清理过期的 sessions
	result, err = db.ExecContext(ctx, `DELETE FROM sessions WHERE expiresAt < ?`, time.Now())
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup expired sessions")
	} else if rows, _ := result.RowsAffected(); rows > 0 {
		log.Debug().Int64("deleted", rows).Msg("Cleaned up expired sessions")
	}
}
