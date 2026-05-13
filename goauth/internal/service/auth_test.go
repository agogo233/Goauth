package service

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"goauth/internal/config"
	"goauth/internal/model"
	"goauth/internal/repo"
	"goauth/internal/util"
)

func setupAuthTestDB(t *testing.T) *sqlx.DB {
	t.Helper()

	db, err := sqlx.Open("sqlite3", ":memory:?_foreign_keys=on")
	require.NoError(t, err, "Failed to open test database")

	// 创建必要的表
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
	CREATE TABLE IF NOT EXISTS user_groups (
		userId TEXT NOT NULL,
		groupId TEXT NOT NULL,
		createdAt TEXT NOT NULL,
		PRIMARY KEY (userId, groupId),
		FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (groupId) REFERENCES groups(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS totp (
		id TEXT PRIMARY KEY,
		userId TEXT NOT NULL UNIQUE,
		secret TEXT NOT NULL,
		createdAt TEXT NOT NULL,
		updatedAt TEXT NOT NULL,
		FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
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
	CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err, "Failed to create schema")

	t.Cleanup(func() {
		db.Close()
	})

	return db
}

func setupAuthTestConfig() *config.Config {
	key := make([]byte, 32)
	rand.Read(key)

	return &config.Config{
		Server: config.ServerConfig{
			AppURL: "http://localhost:3000",
		},
		Session: config.SessionConfig{
			TTL:         24 * time.Hour,
			TTLRemember: 30 * 24 * time.Hour,
		},
		Security: config.SecurityConfig{
			CryptoKey:          key,
			PasswordMin:        8,
			PasswordMinScore:   3,
			LoginMaxAttempts:   5,
			LoginBlockDuration: 30,
		},
		UI: config.UIConfig{
			AppName: "TestApp",
		},
	}
}

func setupAuthService(t *testing.T) (*sqlx.DB, *AuthService) {
	t.Helper()
	db := setupAuthTestDB(t)
	cfg := setupAuthTestConfig()

	userRepo := repo.NewUserRepo(db)
	sessionRepo := repo.NewSessionRepo(db)
	groupRepo := repo.NewGroupRepo(db)
	invitationRepo := repo.NewInvitationRepo(db)
	totpService := NewTotpService(db, cfg)
	protector := util.NewBruteForceProtector(db, cfg.Security.LoginMaxAttempts, cfg.Security.LoginBlockDuration)
	invitationService := NewInvitationService(invitationRepo, groupRepo, db)
	authService := NewAuthService(userRepo, sessionRepo, groupRepo, totpService, invitationService, protector, cfg)

	return db, authService
}

func createTestUser(t *testing.T, db *sqlx.DB, username, password string, opts ...func(*model.User)) *model.User {
	t.Helper()
	ctx := context.Background()

	passwordHash, err := util.HashPassword(password)
	require.NoError(t, err)

	user := &model.User{
		Username:      username,
		PasswordHash:  &passwordHash,
		EmailVerified: true,
		Approved:      true,
	}

	for _, opt := range opts {
		opt(user)
	}

	err = repo.NewUserRepo(db).Create(ctx, user)
	require.NoError(t, err)

	return user
}

func TestAuthService_Login_Success(t *testing.T) {
	db, svc := setupAuthService(t)
	ctx := context.Background()

	// 创建用户
	createTestUser(t, db, "testuser", "Test-Password-2024!")

	// 登录
	resp, err := svc.Login(ctx, &LoginRequest{
		Username: "testuser",
		Password: "Test-Password-2024!",
	}, "127.0.0.1")

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.NotNil(t, resp.User)
	assert.Equal(t, "testuser", resp.User.Username)
	assert.False(t, resp.RequireTotp)
	assert.True(t, resp.ExpiresAt.After(time.Now()))
}

func TestAuthService_Login_WrongPassword(t *testing.T) {
	db, svc := setupAuthService(t)
	ctx := context.Background()

	createTestUser(t, db, "testuser", "Test-Password-2024!")

	resp, err := svc.Login(ctx, &LoginRequest{
		Username: "testuser",
		Password: "Wrong-Password-2024!",
	}, "127.0.0.1")

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Nil(t, resp)
}

func TestAuthService_Login_UserNotFound(t *testing.T) {
	_, svc := setupAuthService(t)
	ctx := context.Background()

	resp, err := svc.Login(ctx, &LoginRequest{
		Username: "nonexistent",
		Password: "Test-Password-2024!",
	}, "127.0.0.1")

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Nil(t, resp)
}

func TestAuthService_Login_UserDisabled(t *testing.T) {
	db, svc := setupAuthService(t)
	ctx := context.Background()

	createTestUser(t, db, "disableduser", "Test-Password-2024!", func(u *model.User) {
		u.Disabled = true
	})

	resp, err := svc.Login(ctx, &LoginRequest{
		Username: "disableduser",
		Password: "Test-Password-2024!",
	}, "127.0.0.1")

	assert.Error(t, err)
	assert.Equal(t, ErrUserDisabled, err)
	assert.Nil(t, resp)
}

func TestAuthService_Login_UserNotApproved(t *testing.T) {
	db, svc := setupAuthService(t)
	ctx := context.Background()

	createTestUser(t, db, "notapproved", "Test-Password-2024!", func(u *model.User) {
		u.Approved = false
	})

	resp, err := svc.Login(ctx, &LoginRequest{
		Username: "notapproved",
		Password: "Test-Password-2024!",
	}, "127.0.0.1")

	assert.Error(t, err)
	assert.Equal(t, ErrUserNotApproved, err)
	assert.Nil(t, resp)
}

func TestAuthService_Login_EmailNotVerified(t *testing.T) {
	db, svc := setupAuthService(t)
	ctx := context.Background()

	createTestUser(t, db, "unverified", "Test-Password-2024!", func(u *model.User) {
		u.EmailVerified = false
	})

	resp, err := svc.Login(ctx, &LoginRequest{
		Username: "unverified",
		Password: "Test-Password-2024!",
	}, "127.0.0.1")

	assert.Error(t, err)
	assert.Equal(t, ErrUserUnverified, err)
	assert.Nil(t, resp)
}

func TestAuthService_Login_RememberMe(t *testing.T) {
	db, svc := setupAuthService(t)
	ctx := context.Background()

	createTestUser(t, db, "rememberuser", "Test-Password-2024!")

	resp, err := svc.Login(ctx, &LoginRequest{
		Username:   "rememberuser",
		Password:   "Test-Password-2024!",
		RememberMe: true,
	}, "127.0.0.1")

	require.NoError(t, err)
	assert.NotNil(t, resp)
	// 记住我应该延长过期时间
	assert.True(t, resp.ExpiresAt.After(time.Now().Add(24*time.Hour)))
}

func TestAuthService_Logout(t *testing.T) {
	db, svc := setupAuthService(t)
	ctx := context.Background()

	createTestUser(t, db, "logoutuser", "Test-Password-2024!")

	// 先登录
	resp, err := svc.Login(ctx, &LoginRequest{
		Username: "logoutuser",
		Password: "Test-Password-2024!",
	}, "127.0.0.1")
	require.NoError(t, err)

	// 登出
	err = svc.Logout(ctx, resp.Token)
	assert.NoError(t, err)

	// 验证 session 已删除
	session, err := repo.NewSessionRepo(db).FindByToken(ctx, resp.Token)
	assert.Error(t, err)
	assert.Nil(t, session)
}

func TestAuthService_ValidateSession(t *testing.T) {
	db, svc := setupAuthService(t)
	ctx := context.Background()

	createTestUser(t, db, "sessionuser", "Test-Password-2024!")

	// 登录
	resp, err := svc.Login(ctx, &LoginRequest{
		Username: "sessionuser",
		Password: "Test-Password-2024!",
	}, "127.0.0.1")
	require.NoError(t, err)

	// 验证 session
	user, err := svc.ValidateSession(ctx, resp.Token)
	require.NoError(t, err)
	assert.Equal(t, "sessionuser", user.Username)
}

func TestAuthService_ValidateSession_InvalidToken(t *testing.T) {
	_, svc := setupAuthService(t)
	ctx := context.Background()

	user, err := svc.ValidateSession(ctx, "invalid-token")
	assert.Error(t, err)
	assert.Nil(t, user)
}

func TestAuthService_Register_FirstUser(t *testing.T) {
	_, svc := setupAuthService(t)
	ctx := context.Background()

	email := "first@example.com"
	resp, err := svc.Register(ctx, &RegisterRequest{
		Username: "firstuser",
		Password: "Correct-Horse-Battery-Staple-2024!",
		Email:    &email,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "firstuser", resp.User.Username)
	assert.True(t, resp.User.IsAdmin, "第一个用户应该是管理员")
	assert.True(t, resp.User.EmailVerified, "第一个用户应该自动验证邮箱")
	assert.True(t, resp.User.Approved, "第一个用户应该自动批准")
	assert.Equal(t, "注册成功", resp.Message)
}

func TestAuthService_Register_SubsequentUser(t *testing.T) {
	db, svc := setupAuthService(t)
	ctx := context.Background()

	// 先创建第一个用户
	createTestUser(t, db, "firstuser", "Test-Password-2024!", func(u *model.User) {
		u.IsAdmin = true
	})

	email := "second@example.com"
	resp, err := svc.Register(ctx, &RegisterRequest{
		Username: "seconduser",
		Password: "Correct-Horse-Battery-Staple-2024!",
		Email:    &email,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "seconduser", resp.User.Username)
	assert.False(t, resp.User.IsAdmin, "后续用户不应该是管理员")
	assert.False(t, resp.User.EmailVerified, "后续用户需要验证邮箱")
	assert.False(t, resp.User.Approved, "后续用户需要审批")
	assert.Equal(t, "注册成功，请等待管理员审批", resp.Message)
}

func TestAuthService_Register_WeakPassword(t *testing.T) {
	_, svc := setupAuthService(t)
	ctx := context.Background()

	resp, err := svc.Register(ctx, &RegisterRequest{
		Username: "weakuser",
		Password: "123", // 太弱
	})

	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestAuthService_Login_ByEmail(t *testing.T) {
	db, svc := setupAuthService(t)
	ctx := context.Background()

	email := "emailuser@example.com"
	createTestUser(t, db, "emailuser", "Test-Password-2024!", func(u *model.User) {
		u.Email = &email
	})

	// 用邮箱登录
	resp, err := svc.Login(ctx, &LoginRequest{
		Username: email,
		Password: "Test-Password-2024!",
	}, "127.0.0.1")

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "emailuser", resp.User.Username)
}
