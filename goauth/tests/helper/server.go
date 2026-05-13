package helper

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"goauth/internal/config"
	"goauth/internal/handler"
	"goauth/internal/middleware"
	"goauth/internal/model"
	"goauth/internal/repo"
	"goauth/internal/service"
	"goauth/internal/util"
)

// TestServer 测试服务器
type TestServer struct {
	DB     *sqlx.DB
	Router *gin.Engine
	Server *httptest.Server
	Cfg    *config.Config

	// Repositories
	UserRepo       *repo.UserRepo
	SessionRepo    *repo.SessionRepo
	GroupRepo      *repo.GroupRepo
	ClientRepo     *repo.ClientRepo
	InvitationRepo *repo.InvitationRepo
	ProxyAuthRepo  *repo.ProxyAuthRepo
	OIDCRepo       *repo.OIDCRepo
	KeyRepo        *repo.KeyRepo

	// Services
	AuthService      *service.AuthService
	UserService      *service.UserService
	GroupService     *service.GroupService
	TotpService      *service.TotpService
	AuditService     *service.AuditService
	InvitationService *service.InvitationService
}

// NewTestServer 创建测试服务器
func NewTestServer(t *testing.T) *TestServer {
	t.Helper()
	gin.SetMode(gin.TestMode)

	// 创建内存数据库
	// _loc=UTC 让 SQLite 驱动自动解析时间字符串为 time.Time
	database, err := sqlx.Open("sqlite3", ":memory:?_foreign_keys=on&_loc=UTC")
	require.NoError(t, err, "Failed to open test database")

	// 运行迁移
	err = runMigrations(database)
	require.NoError(t, err, "Failed to run migrations")

	// 创建测试配置
	cfg := newTestConfig()

	// 创建 repositories
	userRepo := repo.NewUserRepo(database)
	sessionRepo := repo.NewSessionRepo(database)
	groupRepo := repo.NewGroupRepo(database)
	clientRepo := repo.NewClientRepo(database)
	invitationRepo := repo.NewInvitationRepo(database)
	proxyAuthRepo := repo.NewProxyAuthRepo(database)
	oidcRepo := repo.NewOIDCRepo(database)
	keyRepo := repo.NewKeyRepo(database)

	// 创建 services
	protector := util.NewBruteForceProtector(database, cfg.Security.LoginMaxAttempts, cfg.Security.LoginBlockDuration)
	totpService := service.NewTotpService(database, cfg)
	invitationService := service.NewInvitationService(invitationRepo, groupRepo, database)
	authService := service.NewAuthService(userRepo, sessionRepo, groupRepo, totpService, invitationService, protector, cfg)
	userService := service.NewUserService(userRepo, sessionRepo, groupRepo, database, cfg)
	groupService := service.NewGroupService(groupRepo, database)
	auditService := service.NewAuditService(database)

	// 创建 handlers
	authHandler := handler.NewAuthHandler(authService, userService, auditService, cfg)
	userHandler := handler.NewUserHandler(userService, totpService, sessionRepo, cfg)
	adminHandler := handler.NewAdminHandler(
		userService, groupService, auditService, invitationService, totpService,
		userRepo, groupRepo, clientRepo, invitationRepo, proxyAuthRepo,
	)
	proxyAuthHandler := handler.NewProxyAuthHandler(authService, proxyAuthRepo, groupRepo, sessionRepo)

	// 创建 middleware
	authMiddleware := middleware.NewAuthMiddleware(authService, cfg)

	// 设置路由
	router := setupTestRouter(authHandler, userHandler, adminHandler, proxyAuthHandler, authMiddleware)

	// 创建测试服务器
	server := httptest.NewServer(router)

	return &TestServer{
		DB:          database,
		Router:      router,
		Server:      server,
		Cfg:         cfg,
		UserRepo:    userRepo,
		SessionRepo: sessionRepo,
		GroupRepo:   groupRepo,
		ClientRepo:  clientRepo,
		InvitationRepo: invitationRepo,
		ProxyAuthRepo: proxyAuthRepo,
		OIDCRepo: oidcRepo,
		KeyRepo: keyRepo,
		AuthService: authService,
		UserService: userService,
		GroupService: groupService,
		TotpService: totpService,
		AuditService: auditService,
		InvitationService: invitationService,
	}
}

// Close 关闭测试服务器
func (s *TestServer) Close() {
	s.Server.Close()
	s.DB.Close()
}

// newTestConfig 创建测试配置
func newTestConfig() *config.Config {
	// 生成测试用密钥
	cryptoKey := make([]byte, 32)
	rand.Read(cryptoKey)

	cookieKey := make([]byte, 32)
	rand.Read(cookieKey)

	return &config.Config{
		Server: config.ServerConfig{
			Port:           3000,
			Host:           "localhost",
			Environment:    "test",
			AppURL:         "http://localhost:3000",
			BasePath:       "",
			Timezone:       "UTC",
			CookieSecure:   "false", // 测试环境默认不启用 Secure
			CookieSameSite: "lax",
		},
		Database: config.DatabaseConfig{
			Path: ":memory:",
		},
		OIDC: config.OIDCConfig{
			Issuer:         "http://localhost:3000",
			CookieKeys:     []string{base64.StdEncoding.EncodeToString(cookieKey)},
			AccessTokenTTL: 15 * time.Minute,
			IDTokenTTL:     30 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
			SessionTTL:     90 * 24 * time.Hour,
			InteractionTTL: 10 * time.Minute,
			GrantTTL:       30 * 24 * time.Hour,
			ConsentTTL:     30 * 24 * time.Hour,
		},
		Session: config.SessionConfig{
			TTL:         24 * time.Hour,
			TTLRemember: 30 * 24 * time.Hour,
		},
		Security: config.SecurityConfig{
			CryptoKey:        cryptoKey,
			PasswordMin:      8,
			PasswordMinScore: 3,
			LoginMaxAttempts: 10,
			LoginBlockDuration: 30,
			TotpMaxAttempts:  5,
		},
		UI: config.UIConfig{
			AppName:       "Goauth Test",
			AppColor:      "#906bc7",
			SignupEnabled: true,
		},
		Logging: config.LoggingConfig{
			Level: "error", // 测试时只输出错误日志
		},
	}
}

// runMigrations 运行数据库迁移
func runMigrations(db *sqlx.DB) error {
	migrations := []string{
		// Users table
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE,
			username TEXT UNIQUE NOT NULL,
			name TEXT,
			passwordHash TEXT,
			isAdmin INTEGER DEFAULT 0,
			emailVerified INTEGER DEFAULT 0,
			approved INTEGER DEFAULT 0,
			mfaRequired INTEGER DEFAULT 0,
			disabled INTEGER DEFAULT 0,
			createdAt TEXT NOT NULL,
			updatedAt TEXT NOT NULL
		)`,

		// Sessions table
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			userId TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			amr TEXT,
			totpAttempts INTEGER DEFAULT 0,
			rememberMe INTEGER DEFAULT 0,
			expiresAt TEXT NOT NULL,
			createdAt TEXT NOT NULL,
			FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
		)`,

		// Groups table
		`CREATE TABLE IF NOT EXISTS groups (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			mfaRequired INTEGER DEFAULT 0,
			createdBy TEXT NOT NULL,
			createdAt TEXT NOT NULL,
			updatedAt TEXT NOT NULL,
			FOREIGN KEY (createdBy) REFERENCES users(id)
		)`,

		// User-Group association
		`CREATE TABLE IF NOT EXISTS user_groups (
			userId TEXT NOT NULL,
			groupId TEXT NOT NULL,
			createdAt TEXT NOT NULL,
			PRIMARY KEY (userId, groupId),
			FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (groupId) REFERENCES groups(id) ON DELETE CASCADE
		)`,

		// TOTP table
		`CREATE TABLE IF NOT EXISTS totp (
			id TEXT PRIMARY KEY,
			userId TEXT NOT NULL UNIQUE,
			secret TEXT NOT NULL,
			createdAt TEXT NOT NULL,
			updatedAt TEXT NOT NULL,
			FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
		)`,

		// Login attempts table
		`CREATE TABLE IF NOT EXISTS login_attempts (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			ip TEXT NOT NULL,
			success INTEGER DEFAULT 0,
			createdAt TEXT NOT NULL
		)`,

		// Audit log table
		`CREATE TABLE IF NOT EXISTS audit_log (
			id TEXT PRIMARY KEY,
			action TEXT NOT NULL,
			actorId TEXT,
			targetId TEXT,
			details TEXT,
			ip TEXT NOT NULL,
			createdAt TEXT NOT NULL
		)`,

		// Clients table (OIDC clients)
		`CREATE TABLE IF NOT EXISTS clients (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			secret TEXT,
			redirectUris TEXT NOT NULL,
			postLogoutUris TEXT,
			scopes TEXT NOT NULL,
			grantTypes TEXT NOT NULL,
			responseTypes TEXT NOT NULL,
			tokenEndpointAuth TEXT DEFAULT 'client_secret_basic',
			trusted INTEGER DEFAULT 0,
			createdBy TEXT NOT NULL,
			createdAt TEXT NOT NULL,
			updatedAt TEXT NOT NULL,
			FOREIGN KEY (createdBy) REFERENCES users(id)
		)`,

		// Invitations table
		`CREATE TABLE IF NOT EXISTS invitations (
			id TEXT PRIMARY KEY,
			email TEXT,
			username TEXT,
			name TEXT,
			emailVerified INTEGER DEFAULT 0,
			challenge TEXT NOT NULL UNIQUE,
			createdBy TEXT NOT NULL,
			expiresAt TEXT NOT NULL,
			createdAt TEXT NOT NULL,
			FOREIGN KEY (createdBy) REFERENCES users(id)
		)`,

		// Invitation-Group association
		`CREATE TABLE IF NOT EXISTS invitation_groups (
			invitationId TEXT NOT NULL,
			groupId TEXT NOT NULL,
			PRIMARY KEY (invitationId, groupId),
			FOREIGN KEY (invitationId) REFERENCES invitations(id) ON DELETE CASCADE,
			FOREIGN KEY (groupId) REFERENCES groups(id) ON DELETE CASCADE
		)`,

		// ProxyAuth table
		`CREATE TABLE IF NOT EXISTS proxy_auth (
			id TEXT PRIMARY KEY,
			domain TEXT NOT NULL UNIQUE,
			mfaRequired INTEGER DEFAULT 0,
			maxSessionLength INTEGER,
			createdBy TEXT NOT NULL,
			createdAt TEXT NOT NULL,
			updatedAt TEXT NOT NULL,
			FOREIGN KEY (createdBy) REFERENCES users(id)
		)`,

		// ProxyAuth-Group association
		`CREATE TABLE IF NOT EXISTS proxy_auth_groups (
			proxyAuthId TEXT NOT NULL,
			groupId TEXT NOT NULL,
			PRIMARY KEY (proxyAuthId, groupId),
			FOREIGN KEY (proxyAuthId) REFERENCES proxy_auth(id) ON DELETE CASCADE,
			FOREIGN KEY (groupId) REFERENCES groups(id) ON DELETE CASCADE
		)`,

		// OIDC AuthRequests table
		`CREATE TABLE IF NOT EXISTS oidc_auth_requests (
			id TEXT PRIMARY KEY,
			clientId TEXT NOT NULL,
			userId TEXT,
			scopes TEXT,
			redirectUri TEXT,
			state TEXT,
			codeChallenge TEXT,
			codeChallengeMethod TEXT,
			createdAt TEXT NOT NULL,
			expiresAt TEXT NOT NULL,
			FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
		)`,

		// OIDC Tokens table
		`CREATE TABLE IF NOT EXISTS oidc_tokens (
			id TEXT PRIMARY KEY,
			userId TEXT NOT NULL,
			clientId TEXT NOT NULL,
			tokenType TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			scopes TEXT,
			expiresAt TEXT NOT NULL,
			createdAt TEXT NOT NULL,
			FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
		)`,

		// OIDC Payloads table (通用 OIDC 存储)
		// 注意：测试环境移除外键约束以简化测试
		`CREATE TABLE IF NOT EXISTS oidc_payloads (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			payload TEXT NOT NULL,
			grantId TEXT,
			userCode TEXT,
			uid TEXT,
			expiresAt TEXT,
			consumedAt TEXT,
			accountId TEXT
		)`,

		// Keys table (for JWT signing)
		`CREATE TABLE IF NOT EXISTS keys (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			privateKey TEXT,
			publicKey TEXT,
			value TEXT,
			expiresAt TEXT,
			createdAt TEXT NOT NULL
		)`,

		// Indexes
		`CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_userId ON sessions(userId)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expiresAt ON sessions(expiresAt)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_createdAt ON login_attempts(createdAt)`,
		`CREATE INDEX IF NOT EXISTS idx_invitations_challenge ON invitations(challenge)`,
		`CREATE INDEX IF NOT EXISTS idx_oidc_tokens_token ON oidc_tokens(token)`,
	}

	for i, migration := range migrations {
		if _, err := db.Exec(migration); err != nil {
			return err
		}
		_ = i // avoid unused variable warning
	}
	return nil
}

// setupTestRouter 设置测试路由
func setupTestRouter(authHandler *handler.AuthHandler, userHandler *handler.UserHandler, adminHandler *handler.AdminHandler, proxyAuthHandler *handler.ProxyAuthHandler, authMiddleware *middleware.AuthMiddleware) *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())

	// ProxyAuth routes (for Traefik/Nginx)
	router.GET("/authz/forward-auth", proxyAuthHandler.ForwardAuth)
	router.GET("/authz/auth-request", proxyAuthHandler.AuthRequest)

	// API routes
	api := router.Group("/api")
	{
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
		}

		// MFA setup routes (accessible by pwd-mfa-setup-required users)
		mfaSetup := api.Group("/mfa-setup")
		mfaSetup.Use(authMiddleware.RequireMfaSetup())
		{
			mfaSetup.GET("/me", userHandler.GetMe)
			mfaSetup.POST("/totp/setup", userHandler.SetupTotp)
			mfaSetup.POST("/totp/verify", userHandler.VerifyTotp)
		}

		// Admin routes (authenticated + admin)
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

	return router
}

// CreateUser 创建测试用户
func (s *TestServer) CreateUser(t *testing.T, opts ...UserOption) *model.User {
	t.Helper()
	ctx := context.Background()

	// 生成唯一标识符
	uniqueID := generateUniqueID()

	// 默认密码
	defaultPassword := "My-Test-Pass-2024-Secure!"
	defaultPasswordHash, err := util.HashPassword(defaultPassword)
	require.NoError(t, err, "Failed to hash password")

	user := &model.User{
		Username:      "user_" + uniqueID,
		PasswordHash:  &defaultPasswordHash,
		Email:         strPtr("user_" + uniqueID + "@test.example.com"),
		Name:          strPtr("Test User"),
		IsAdmin:       false,
		EmailVerified: true,
		Approved:      true,
		MFARequired:   false,
		Disabled:      false,
	}

	// 应用选项（可能覆盖密码）
	for _, opt := range opts {
		opt(user)
	}

	err = s.UserRepo.Create(ctx, user)
	require.NoError(t, err, "Failed to create user")

	return user
}

// generateUniqueID 生成唯一标识符
func generateUniqueID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// CreateAdmin 创建管理员用户
func (s *TestServer) CreateAdmin(t *testing.T) *model.User {
	t.Helper()
	return s.CreateUser(t,
		WithUsername("admin"),
		WithEmail("admin@example.com"),
		WithName("Admin User"),
		WithIsAdmin(true),
	)
}

// Login 登录并返回 session token
func (s *TestServer) Login(t *testing.T, username, password string) string {
	t.Helper()

	resp, err := s.AuthService.Login(context.Background(), &service.LoginRequest{
		Username:   username,
		Password:   password,
		RememberMe: false,
	}, "127.0.0.1")

	require.NoError(t, err, "Login failed")
	require.False(t, resp.RequireTotp, "TOTP required but not expected")

	return resp.Token
}

// LoginAsUser 创建并登录一个测试用户
func (s *TestServer) LoginAsUser(t *testing.T, opts ...UserOption) (*model.User, string) {
	t.Helper()

	// 默认密码
	defaultPassword := "My-Test-Pass-2024-Secure!"

	// 确保密码使用默认值
	opts = append(opts, WithPassword(defaultPassword))

	user := s.CreateUser(t, opts...)
	token := s.Login(t, user.Username, defaultPassword)
	return user, token
}

// UserOption 用户创建选项
type UserOption func(*model.User)

// WithUsername 设置用户名
func WithUsername(username string) UserOption {
	return func(u *model.User) {
		u.Username = username
	}
}

// WithEmail 设置邮箱
func WithEmail(email string) UserOption {
	return func(u *model.User) {
		if email == "" {
			u.Email = nil
		} else {
			u.Email = &email
		}
	}
}

// WithNoEmail 显式设置无邮箱
func WithNoEmail() UserOption {
	return func(u *model.User) {
		u.Email = nil
	}
}

// WithName 设置名称
func WithName(name string) UserOption {
	return func(u *model.User) {
		u.Name = &name
	}
}

// WithPassword 设置密码
func WithPassword(password string) UserOption {
	return func(u *model.User) {
		hash, err := util.HashPassword(password)
		if err != nil {
			panic(err)
		}
		u.PasswordHash = &hash
	}
}

// WithIsAdmin 设置管理员
func WithIsAdmin(isAdmin bool) UserOption {
	return func(u *model.User) {
		u.IsAdmin = isAdmin
	}
}

// WithEmailVerified 设置邮箱验证状态
func WithEmailVerified(verified bool) UserOption {
	return func(u *model.User) {
		u.EmailVerified = verified
	}
}

// WithApproved 设置批准状态
func WithApproved(approved bool) UserOption {
	return func(u *model.User) {
		u.Approved = approved
	}
}

// WithDisabled 设置禁用状态
func WithDisabled(disabled bool) UserOption {
	return func(u *model.User) {
		u.Disabled = disabled
	}
}

// WithUserMFARequired 设置用户 MFA 要求
func WithUserMFARequired(required bool) UserOption {
	return func(u *model.User) {
		u.MFARequired = required
	}
}

// CreateGroup 创建测试分组
func (s *TestServer) CreateGroup(t *testing.T, opts ...GroupOption) *model.Group {
	t.Helper()
	ctx := context.Background()

	group := &model.Group{
		Name:        "test-group",
		MFARequired: false,
	}

	for _, opt := range opts {
		opt(group)
	}

	// 如果没有设置 createdBy，创建一个系统用户
	if group.CreatedBy == "" {
		group.CreatedBy = s.ensureSystemUser(t)
	} else if group.CreatedBy == "test-system" {
		// 确保系统用户存在
		group.CreatedBy = s.ensureSystemUser(t)
	}

	// 确保时间字段已设置
	if group.CreatedAt.IsZero() {
		group.CreatedAt = model.Now()
	}
	if group.UpdatedAt.IsZero() {
		group.UpdatedAt = model.Now()
	}

	err := s.GroupRepo.Create(ctx, group)
	require.NoError(t, err, "Failed to create group")

	return group
}

// ensureSystemUser 确保系统用户存在，返回其 ID
func (s *TestServer) ensureSystemUser(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	// 尝试查找系统用户
	user, err := s.UserRepo.FindByUsername(ctx, "test-system")
	if err == nil {
		return user.ID
	}

	// 创建系统用户
	email := "test-system@" + generateUniqueID() + ".test"
	systemUser := &model.User{
		ID:        "system-" + generateUniqueID(),
		Username:  "test-system",
		Email:     &email,
		IsAdmin:   true,
		Approved:  true,
		CreatedAt: model.CustomTime{Time: time.Now()},
		UpdatedAt: model.CustomTime{Time: time.Now()},
	}
	err = s.UserRepo.Create(ctx, systemUser)
	require.NoError(t, err, "Failed to create system user")
	return systemUser.ID
}

// CreateClient 创建测试 OIDC 客户端
func (s *TestServer) CreateClient(t *testing.T, opts ...ClientOption) *model.Client {
	t.Helper()
	ctx := context.Background()

	redirectURIs, _ := json.Marshal([]string{"http://localhost:3000/callback"})
	postLogoutUris, _ := json.Marshal([]string{"http://localhost:3000/logout"})
	scopes, _ := json.Marshal([]string{"openid", "profile", "email"})
	grantTypes, _ := json.Marshal([]string{"authorization_code", "refresh_token"})
	responseTypes, _ := json.Marshal([]string{"code"})

	client := &model.Client{
		ID:             "test-client",
		Name:           "Test Client",
		RedirectURIs:   string(redirectURIs),
		PostLogoutURIs: string(postLogoutUris),
		Scopes:         string(scopes),
		GrantTypes:     string(grantTypes),
		ResponseTypes:  string(responseTypes),
		Trusted:        false,
	}

	for _, opt := range opts {
		opt(client)
	}

	// 如果没有设置 createdBy，创建一个系统用户
	if client.CreatedBy == "" {
		client.CreatedBy = s.ensureSystemUser(t)
	} else if client.CreatedBy == "test-system" {
		// 确保系统用户存在
		client.CreatedBy = s.ensureSystemUser(t)
	}

	err := s.ClientRepo.Create(ctx, client)
	require.NoError(t, err, "Failed to create client")

	return client
}

// GroupOption 分组创建选项
type GroupOption func(*model.Group)

// WithGroupName 设置分组名称
func WithGroupName(name string) GroupOption {
	return func(g *model.Group) {
		g.Name = name
	}
}

// WithMFARequired 设置 MFA 要求
func WithMFARequired(required bool) GroupOption {
	return func(g *model.Group) {
		g.MFARequired = required
	}
}

// WithGroupCreatedBy 设置分组创建者
func WithGroupCreatedBy(createdBy string) GroupOption {
	return func(g *model.Group) {
		g.CreatedBy = createdBy
	}
}

// AddUserToGroup 将用户添加到分组
func (s *TestServer) AddUserToGroup(t *testing.T, userID, groupID string) {
	t.Helper()
	ctx := context.Background()

	userGroup := &model.UserGroup{
		UserID:    userID,
		GroupID:   groupID,
		CreatedAt: model.Now(),
	}

	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO user_groups (userId, groupId, createdAt) VALUES (?, ?, ?)`,
		userGroup.UserID, userGroup.GroupID, userGroup.CreatedAt,
	)
	require.NoError(t, err, "Failed to add user to group")
}

// ClientOption 客户端创建选项
type ClientOption func(*model.Client)

// WithClientID 设置客户端 ID
func WithClientID(id string) ClientOption {
	return func(c *model.Client) {
		c.ID = id
	}
}

// WithClientName 设置客户端名称
func WithClientName(name string) ClientOption {
	return func(c *model.Client) {
		c.Name = name
	}
}

// WithClientSecret 设置客户端密钥
func WithClientSecret(secret string) ClientOption {
	return func(c *model.Client) {
		c.Secret = &secret
	}
}

// WithRedirectURIs 设置重定向 URI
func WithRedirectURIs(uris []string) ClientOption {
	return func(c *model.Client) {
		data, _ := json.Marshal(uris)
		c.RedirectURIs = string(data)
	}
}

// WithScopes 设置权限范围
func WithScopes(scopes []string) ClientOption {
	return func(c *model.Client) {
		data, _ := json.Marshal(scopes)
		c.Scopes = string(data)
	}
}

// WithTrusted 设置信任状态
func WithTrusted(trusted bool) ClientOption {
	return func(c *model.Client) {
		c.Trusted = trusted
	}
}

// strPtr 返回字符串指针
func strPtr(s string) *string {
	return &s
}
