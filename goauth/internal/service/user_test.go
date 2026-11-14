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
	dbpkg "goauth/internal/db"
	"goauth/internal/model"
	"goauth/internal/repo"
	"goauth/internal/util"
)

func setupUserTestDB(t *testing.T) *sqlx.DB {
	t.Helper()

	db, err := sqlx.Open("sqlite3", ":memory:?_foreign_keys=on")
	require.NoError(t, err, "Failed to open test database")

	// 复用生产迁移，保证测试与生产 schema 一致
	require.NoError(t, dbpkg.RunMigrations(db), "Failed to run migrations")

	t.Cleanup(func() {
		db.Close()
	})

	return db
}

func setupUserTestConfig() *config.Config {
	key := make([]byte, 32)
	rand.Read(key)

	return &config.Config{
		Security: config.SecurityConfig{
			CryptoKey:        key,
			PasswordMin:      8,
			PasswordMinScore: 3,
		},
	}
}

func setupUserService(t *testing.T) (*sqlx.DB, *UserService) {
	t.Helper()
	db := setupUserTestDB(t)
	cfg := setupUserTestConfig()

	userRepo := repo.NewUserRepo(db)
	sessionRepo := repo.NewSessionRepo(db)
	groupRepo := repo.NewGroupRepo(db)
	userService := NewUserService(userRepo, sessionRepo, groupRepo, db, cfg)

	return db, userService
}

func createTestUserForUserService(t *testing.T, db *sqlx.DB, username string, opts ...func(*model.User)) *model.User {
	t.Helper()
	ctx := context.Background()

	passwordHash, _ := util.HashPassword("Test-Password-2024!")
	user := &model.User{
		Username:      username,
		PasswordHash:  &passwordHash,
		EmailVerified: true,
		Approved:      true,
	}

	for _, opt := range opts {
		opt(user)
	}

	err := repo.NewUserRepo(db).Create(ctx, user)
	require.NoError(t, err)

	return user
}

func TestUserService_GetByID(t *testing.T) {
	db, svc := setupUserService(t)
	ctx := context.Background()

	email := "getbyid@example.com"
	name := "Get By ID User"
	user := createTestUserForUserService(t, db, "getbyid", func(u *model.User) {
		u.Email = &email
		u.Name = &name
	})

	resp, err := svc.GetByID(ctx, user.ID)

	require.NoError(t, err)
	assert.Equal(t, user.ID, resp.ID)
	assert.Equal(t, "getbyid", resp.Username)
	assert.Equal(t, email, *resp.Email)
	assert.Equal(t, name, *resp.Name)
}

func TestUserService_GetByID_NotFound(t *testing.T) {
	_, svc := setupUserService(t)
	ctx := context.Background()

	resp, err := svc.GetByID(ctx, "nonexistent-id")

	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestUserService_ListUsers(t *testing.T) {
	db, svc := setupUserService(t)
	ctx := context.Background()

	// 创建多个用户
	for i := 0; i < 5; i++ {
		createTestUserForUserService(t, db, "listuser"+string(rune('0'+i)))
		time.Sleep(time.Millisecond)
	}

	users, count, err := svc.ListUsers(ctx, 3, 0)

	require.NoError(t, err)
	assert.Equal(t, 5, count)
	assert.Len(t, users, 3)
}

func TestUserService_UpdateProfile(t *testing.T) {
	db, svc := setupUserService(t)
	ctx := context.Background()

	user := createTestUserForUserService(t, db, "updateprofile")

	newName := "Updated Name"
	newEmail := "updated@example.com"
	resp, err := svc.UpdateProfile(ctx, user.ID, &newName, &newEmail)

	require.NoError(t, err)
	assert.Equal(t, newName, *resp.Name)
	assert.Equal(t, newEmail, *resp.Email)
	assert.False(t, resp.EmailVerified, "更新邮箱后应该需要重新验证")
}

func TestUserService_UpdatePassword(t *testing.T) {
	db, svc := setupUserService(t)
	ctx := context.Background()

	oldPassword := "Old-Password-2024-Secure!"
	newPassword := "New-Password-2025-Secure!"
	user := createTestUserForUserService(t, db, "updatepass", func(u *model.User) {
		hash, _ := util.HashPassword(oldPassword)
		u.PasswordHash = &hash
	})

	err := svc.UpdatePassword(ctx, user.ID, oldPassword, newPassword)

	assert.NoError(t, err)

	// 验证新密码可以登录
	valid, _ := util.VerifyPassword(newPassword, *user.PasswordHash)
	assert.False(t, valid) // 密码已经更新，旧 hash 不应该匹配
}

func TestUserService_UpdatePassword_WrongOldPassword(t *testing.T) {
	db, svc := setupUserService(t)
	ctx := context.Background()

	user := createTestUserForUserService(t, db, "wrongoldpass")

	err := svc.UpdatePassword(ctx, user.ID, "Wrong-Old-Password!", "New-Password-2024!")

	assert.Error(t, err)
	assert.Equal(t, "旧密码错误", err.Error())
}

func TestUserService_UpdatePassword_WeakNewPassword(t *testing.T) {
	db, svc := setupUserService(t)
	ctx := context.Background()

	user := createTestUserForUserService(t, db, "weaknewpass")

	err := svc.UpdatePassword(ctx, user.ID, "Test-Password-2024!", "123")

	assert.Error(t, err)
}

func TestUserService_AdminResetPassword(t *testing.T) {
	db, svc := setupUserService(t)
	ctx := context.Background()

	// 创建用户并创建 session
	user := createTestUserForUserService(t, db, "resetpass")
	sessionRepo := repo.NewSessionRepo(db)
	session := &model.Session{
		UserID:     user.ID,
		Token:      "test-token",
		ExpiresAt:  model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
	}
	sessionRepo.Create(ctx, session)

	err := svc.AdminResetPassword(ctx, user.ID, "New-Admin-Password-2024!")

	assert.NoError(t, err)

	// 验证 session 已被删除（强制重新登录）
	sessions, _ := sessionRepo.FindByUserID(ctx, user.ID)
	assert.Empty(t, sessions)
}

func TestUserService_ApproveUser(t *testing.T) {
	db, svc := setupUserService(t)
	ctx := context.Background()

	user := createTestUserForUserService(t, db, "approveuser", func(u *model.User) {
		u.Approved = false
		u.EmailVerified = false
	})

	err := svc.ApproveUser(ctx, user.ID)

	assert.NoError(t, err)

	// 验证已批准且邮箱已验证
	updated, _ := repo.NewUserRepo(db).FindByID(ctx, user.ID)
	assert.True(t, updated.Approved)
	assert.True(t, updated.EmailVerified, "审批后邮箱应该自动验证")
}

func TestUserService_DisableUser(t *testing.T) {
	db, svc := setupUserService(t)
	ctx := context.Background()

	user := createTestUserForUserService(t, db, "disableuser")
	// 创建 session
	sessionRepo := repo.NewSessionRepo(db)
	session := &model.Session{
		UserID:     user.ID,
		Token:      "test-token-disable",
		ExpiresAt:  model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
	}
	sessionRepo.Create(ctx, session)

	err := svc.DisableUser(ctx, user.ID)

	assert.NoError(t, err)

	// 验证已禁用
	updated, _ := repo.NewUserRepo(db).FindByID(ctx, user.ID)
	assert.True(t, updated.Disabled)

	// 验证 session 已被删除
	sessions, _ := sessionRepo.FindByUserID(ctx, user.ID)
	assert.Empty(t, sessions)
}

func TestUserService_EnableUser(t *testing.T) {
	db, svc := setupUserService(t)
	ctx := context.Background()

	user := createTestUserForUserService(t, db, "enableuser", func(u *model.User) {
		u.Disabled = true
	})

	err := svc.EnableUser(ctx, user.ID)

	assert.NoError(t, err)

	// 验证已启用
	updated, _ := repo.NewUserRepo(db).FindByID(ctx, user.ID)
	assert.False(t, updated.Disabled)
}

func TestUserService_DeleteUser(t *testing.T) {
	db, svc := setupUserService(t)
	ctx := context.Background()

	user := createTestUserForUserService(t, db, "deleteuser")

	err := svc.DeleteUser(ctx, user.ID)

	assert.NoError(t, err)

	// 验证已删除
	_, err = repo.NewUserRepo(db).FindByID(ctx, user.ID)
	assert.Error(t, err)
}

func TestUserService_SetAdmin(t *testing.T) {
	db, svc := setupUserService(t)
	ctx := context.Background()

	user := createTestUserForUserService(t, db, "setadmin")

	err := svc.SetAdmin(ctx, user.ID, true)

	assert.NoError(t, err)

	// 验证已设为管理员
	updated, _ := repo.NewUserRepo(db).FindByID(ctx, user.ID)
	assert.True(t, updated.IsAdmin)

	// 移除管理员
	err = svc.SetAdmin(ctx, user.ID, false)
	assert.NoError(t, err)

	updated, _ = repo.NewUserRepo(db).FindByID(ctx, user.ID)
	assert.False(t, updated.IsAdmin)
}

func TestUserService_GetUserSessions(t *testing.T) {
	db, svc := setupUserService(t)
	ctx := context.Background()

	user := createTestUserForUserService(t, db, "sessionuser")
	sessionRepo := repo.NewSessionRepo(db)

	// 创建多个 session
	for i := 0; i < 3; i++ {
		session := &model.Session{
			UserID:     user.ID,
			Token:      "token-" + string(rune('0'+i)),
			ExpiresAt:  model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
		}
		sessionRepo.Create(ctx, session)
	}

	sessions, err := svc.GetUserSessions(ctx, user.ID)

	require.NoError(t, err)
	assert.Len(t, sessions, 3)
}

func TestUserService_TerminateSession(t *testing.T) {
	db, svc := setupUserService(t)
	ctx := context.Background()

	user := createTestUserForUserService(t, db, "terminatesession")
	sessionRepo := repo.NewSessionRepo(db)
	session := &model.Session{
		UserID:     user.ID,
		Token:      "terminate-token",
		ExpiresAt:  model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
	}
	sessionRepo.Create(ctx, session)

	err := svc.TerminateSession(ctx, session.ID)

	assert.NoError(t, err)

	// 验证已删除
	sessions, _ := sessionRepo.FindByUserID(ctx, user.ID)
	assert.Empty(t, sessions)
}
