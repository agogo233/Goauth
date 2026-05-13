package middleware

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"goauth/internal/config"
	"goauth/internal/model"
	"goauth/internal/repo"
	"goauth/internal/service"
	"goauth/internal/util"
)

func setupAuthMiddlewareTestDB(t *testing.T) *sqlx.DB {
	t.Helper()

	db, err := sqlx.Open("sqlite3", ":memory:?_foreign_keys=on")
	require.NoError(t, err)

	schema := `
	CREATE TABLE IF NOT EXISTS users (
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
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		userId TEXT NOT NULL,
		token TEXT NOT NULL UNIQUE,
		amr TEXT,
		rememberMe INTEGER DEFAULT 0,
		expiresAt TEXT NOT NULL,
		createdAt TEXT NOT NULL,
		FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS groups (
		id TEXT PRIMARY KEY,
		name TEXT UNIQUE NOT NULL,
		mfaRequired INTEGER DEFAULT 0,
		createdBy TEXT NOT NULL,
		createdAt TEXT NOT NULL,
		updatedAt TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS totp (
		id TEXT PRIMARY KEY,
		userId TEXT NOT NULL UNIQUE,
		secret TEXT NOT NULL,
		createdAt TEXT NOT NULL,
		updatedAt TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS login_attempts (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		ip TEXT NOT NULL,
		success INTEGER DEFAULT 0,
		createdAt TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
	CREATE INDEX IF NOT EXISTS idx_sessions_userId ON sessions(userId);
	CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
	})

	return db
}

func setupAuthMiddlewareTestConfig() *config.Config {
	key := make([]byte, 32)
	rand.Read(key)

	return &config.Config{
		Session: config.SessionConfig{
			TTL:         24 * time.Hour,
			TTLRemember: 30 * 24 * time.Hour,
		},
		Security: config.SecurityConfig{
			CryptoKey:          key,
			LoginMaxAttempts:   5,
			LoginBlockDuration: 30,
		},
	}
}

func setupAuthMiddleware(t *testing.T) (*sqlx.DB, *AuthMiddleware, *service.AuthService, *config.Config) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db := setupAuthMiddlewareTestDB(t)
	cfg := setupAuthMiddlewareTestConfig()

	userRepo := repo.NewUserRepo(db)
	sessionRepo := repo.NewSessionRepo(db)
	groupRepo := repo.NewGroupRepo(db)
	invitationRepo := repo.NewInvitationRepo(db)
	totpService := service.NewTotpService(db, cfg)
	protector := util.NewBruteForceProtector(db, cfg.Security.LoginMaxAttempts, cfg.Security.LoginBlockDuration)
	invitationService := service.NewInvitationService(invitationRepo, groupRepo, db)
	authService := service.NewAuthService(userRepo, sessionRepo, groupRepo, totpService, invitationService, protector, cfg)
	authMiddleware := NewAuthMiddleware(authService, cfg)

	return db, authMiddleware, authService, cfg
}

func createTestUserForMiddleware(t *testing.T, db *sqlx.DB, username string, isAdmin bool) *model.User {
	t.Helper()
	ctx := context.Background()

	passwordHash, _ := util.HashPassword("Test-Password-2024!")
	user := &model.User{
		Username:      username,
		PasswordHash:  &passwordHash,
		IsAdmin:       isAdmin,
		EmailVerified: true,
		Approved:      true,
	}

	err := repo.NewUserRepo(db).Create(ctx, user)
	require.NoError(t, err)

	return user
}

func createTestSession(t *testing.T, db *sqlx.DB, userID string) string {
	t.Helper()
	ctx := context.Background()

	token := "test-token-" + userID
	session := &model.Session{
		UserID:     userID,
		Token:      token,
		ExpiresAt:  model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
	}

	err := repo.NewSessionRepo(db).Create(ctx, session)
	require.NoError(t, err)

	return token
}

func TestAuthMiddleware_RequireAuth_Success_Cookie(t *testing.T) {
	db, authMiddleware, _, _ := setupAuthMiddleware(t)

	user := createTestUserForMiddleware(t, db, "testuser", false)
	token := createTestSession(t, db, user.ID)

	// 创建测试路由
	router := gin.New()
	router.GET("/protected", authMiddleware.RequireAuth(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 创建请求
	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthMiddleware_RequireAuth_Success_BearerToken(t *testing.T) {
	db, authMiddleware, _, _ := setupAuthMiddleware(t)

	user := createTestUserForMiddleware(t, db, "beareruser", false)
	token := createTestSession(t, db, user.ID)

	router := gin.New()
	router.GET("/protected", authMiddleware.RequireAuth(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthMiddleware_RequireAuth_NoToken(t *testing.T) {
	_, authMiddleware, _, _ := setupAuthMiddleware(t)

	router := gin.New()
	router.GET("/protected", authMiddleware.RequireAuth(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_RequireAuth_InvalidToken(t *testing.T) {
	_, authMiddleware, _, _ := setupAuthMiddleware(t)

	router := gin.New()
	router.GET("/protected", authMiddleware.RequireAuth(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: "invalid-token",
	})
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_RequireAuth_ExpiredSession(t *testing.T) {
	db, authMiddleware, _, _ := setupAuthMiddleware(t)

	user := createTestUserForMiddleware(t, db, "expireduser", false)

	// 创建过期的 session
	ctx := context.Background()
	token := "expired-token"
	session := &model.Session{
		UserID:     user.ID,
		Token:      token,
		ExpiresAt:  model.CustomTime{Time: time.Now().Add(-1 * time.Hour)}, // 已过期
	}
	repo.NewSessionRepo(db).Create(ctx, session)

	router := gin.New()
	router.GET("/protected", authMiddleware.RequireAuth(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_RequireAuth_DisabledUser(t *testing.T) {
	db, authMiddleware, _, _ := setupAuthMiddleware(t)

	user := createTestUserForMiddleware(t, db, "disableduser", false)
	// 禁用用户
	user.Disabled = true
	repo.NewUserRepo(db).Update(context.Background(), user)

	token := createTestSession(t, db, user.ID)

	router := gin.New()
	router.GET("/protected", authMiddleware.RequireAuth(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_RequireAdmin_Success(t *testing.T) {
	db, authMiddleware, _, _ := setupAuthMiddleware(t)

	user := createTestUserForMiddleware(t, db, "adminuser", true)
	token := createTestSession(t, db, user.ID)

	router := gin.New()
	router.GET("/admin",
		authMiddleware.RequireAuth(),
		authMiddleware.RequireAdmin(),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "admin success"})
		},
	)

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthMiddleware_RequireAdmin_NotAdmin(t *testing.T) {
	db, authMiddleware, _, _ := setupAuthMiddleware(t)

	user := createTestUserForMiddleware(t, db, "normaluser", false)
	token := createTestSession(t, db, user.ID)

	router := gin.New()
	router.GET("/admin",
		authMiddleware.RequireAuth(),
		authMiddleware.RequireAdmin(),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "admin success"})
		},
	)

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAuthMiddleware_OptionalAuth_WithToken(t *testing.T) {
	db, authMiddleware, _, _ := setupAuthMiddleware(t)

	user := createTestUserForMiddleware(t, db, "optionaluser", false)
	token := createTestSession(t, db, user.ID)

	router := gin.New()
	router.GET("/optional", authMiddleware.OptionalAuth(), func(c *gin.Context) {
		userID, exists := c.Get("userID")
		if exists {
			c.JSON(http.StatusOK, gin.H{"userID": userID})
		} else {
			c.JSON(http.StatusOK, gin.H{"userID": nil})
		}
	})

	req := httptest.NewRequest("GET", "/optional", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// 验证用户信息已设置
	assert.Contains(t, w.Body.String(), user.ID)
}

func TestAuthMiddleware_OptionalAuth_WithoutToken(t *testing.T) {
	_, authMiddleware, _, _ := setupAuthMiddleware(t)

	router := gin.New()
	router.GET("/optional", authMiddleware.OptionalAuth(), func(c *gin.Context) {
		userID, exists := c.Get("userID")
		if exists {
			c.JSON(http.StatusOK, gin.H{"userID": userID})
		} else {
			c.JSON(http.StatusOK, gin.H{"userID": nil})
		}
	})

	req := httptest.NewRequest("GET", "/optional", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// 验证无用户信息
	assert.Contains(t, w.Body.String(), "null")
}

func TestAuthMiddleware_ContextValues(t *testing.T) {
	db, authMiddleware, _, _ := setupAuthMiddleware(t)

	user := createTestUserForMiddleware(t, db, "contextuser", true)
	token := createTestSession(t, db, user.ID)

	var capturedUserID, capturedUsername string
	var capturedIsAdmin bool

	router := gin.New()
	router.GET("/context", authMiddleware.RequireAuth(), func(c *gin.Context) {
		if v, exists := c.Get("userID"); exists {
			capturedUserID = v.(string)
		}
		if v, exists := c.Get("username"); exists {
			capturedUsername = v.(string)
		}
		if v, exists := c.Get("isAdmin"); exists {
			capturedIsAdmin = v.(bool)
		}
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	req := httptest.NewRequest("GET", "/context", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, user.ID, capturedUserID)
	assert.Equal(t, "contextuser", capturedUsername)
	assert.True(t, capturedIsAdmin)
}

func TestAuthMiddleware_SessionRefresh(t *testing.T) {
	db, authMiddleware, _, cfg := setupAuthMiddleware(t)

	user := createTestUserForMiddleware(t, db, "refreshuser", false)

	// 创建一个即将过期的 session（剩余时间少于 TTL 的一半）
	ctx := context.Background()
	token := "refresh-token"
	ttl := cfg.Session.TTL
	// 设置过期时间为当前时间 + TTL/4（少于一半）
	expiresAt := time.Now().Add(ttl / 4)
	session := &model.Session{
		UserID:     user.ID,
		Token:      token,
		ExpiresAt:  model.CustomTime{Time: expiresAt},
		RememberMe: false,
	}
	err := repo.NewSessionRepo(db).Create(ctx, session)
	require.NoError(t, err)

	router := gin.New()
	router.GET("/protected", authMiddleware.RequireAuth(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// 验证 session 已续期
	updatedSession, err := repo.NewSessionRepo(db).FindByToken(ctx, token)
	require.NoError(t, err)
	// 新的过期时间应该大于原来的过期时间
	assert.True(t, updatedSession.ExpiresAt.Time.After(expiresAt))
	// 新的过期时间应该接近 TTL
	expectedNewExpiry := time.Now().Add(ttl)
	diff := updatedSession.ExpiresAt.Time.Sub(expectedNewExpiry)
	// 允许 1 秒的误差
	assert.Less(t, diff.Abs(), time.Second)
}

func TestAuthMiddleware_SessionNoRefresh(t *testing.T) {
	db, authMiddleware, _, cfg := setupAuthMiddleware(t)

	user := createTestUserForMiddleware(t, db, "norefreshuser", false)

	// 创建一个不需要续期的 session（剩余时间大于 TTL 的一半）
	ctx := context.Background()
	token := "norefresh-token"
	ttl := cfg.Session.TTL
	// 设置过期时间为当前时间 + TTL * 3/4（大于一半）
	expiresAt := time.Now().Add(ttl * 3 / 4)
	session := &model.Session{
		UserID:     user.ID,
		Token:      token,
		ExpiresAt:  model.CustomTime{Time: expiresAt},
		RememberMe: false,
	}
	err := repo.NewSessionRepo(db).Create(ctx, session)
	require.NoError(t, err)

	router := gin.New()
	router.GET("/protected", authMiddleware.RequireAuth(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: token,
	})
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// 验证 session 未续期（过期时间应该基本不变）
	updatedSession, err := repo.NewSessionRepo(db).FindByToken(ctx, token)
	require.NoError(t, err)
	// 过期时间应该几乎相同（允许 1 秒误差）
	diff := updatedSession.ExpiresAt.Time.Sub(expiresAt)
	assert.Less(t, diff.Abs(), time.Second)
}
