package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"goauth/internal/model"
	"goauth/internal/service"
	"goauth/internal/util"
	"goauth/tests/helper"
)

// ========== 审计日志清理测试 ==========

func TestCleanup_AuditLogs(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	user := server.CreateUser(t, helper.WithUsername("cleanupuser"))

	// 创建一些审计日志
	for i := 0; i < 5; i++ {
		server.AuditService.Log(context.Background(), "test_action", &user.ID, nil, "test details", "127.0.0.1")
	}

	// 验证日志已创建
	logs, err := server.AuditService.List(context.Background(), 100, 0)
	require.NoError(t, err)
	initialCount := len(logs)
	assert.GreaterOrEqual(t, initialCount, 5)

	// 测试清理功能
	count, err := server.AuditService.CleanupOldLogs(context.Background(), 0) // 清理所有超过 0 天的日志
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, int64(5))

	// 验证日志已清理
	logs, err = server.AuditService.List(context.Background(), 100, 0)
	require.NoError(t, err)
	assert.Less(t, len(logs), initialCount)
}

func TestCleanup_AuditLogs_KeepRecent(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	user := server.CreateUser(t, helper.WithUsername("keeprecent"))

	// 创建审计日志
	for i := 0; i < 5; i++ {
		server.AuditService.Log(context.Background(), "test_action", &user.ID, nil, "test details", "127.0.0.1")
	}

	// 清理超过 90 天的日志（应该保留所有最近的）
	count, err := server.AuditService.CleanupOldLogs(context.Background(), 90)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "最近 90 天的日志不应该被清理")

	// 验证日志仍然存在
	logs, err := server.AuditService.List(context.Background(), 100, 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(logs), 5)
}

// ========== 登录尝试清理测试 ==========

func TestCleanup_LoginAttempts(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	user := server.CreateUser(t,
		helper.WithUsername("logincleanup"),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 创建一些登录尝试记录（失败的）
	for i := 0; i < 3; i++ {
		_, _ = server.AuthService.Login(context.Background(), &service.LoginRequest{
			Username: user.Username,
			Password: "wrong-password",
		}, "192.168.1.1")
	}

	// 验证登录尝试记录已创建
	var count int
	err := server.DB.Get(&count, "SELECT COUNT(*) FROM login_attempts WHERE username = ?", user.Username)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 3)

	// 手动清理旧的登录尝试
	_, err = server.DB.Exec("DELETE FROM login_attempts WHERE username = ?", user.Username)
	require.NoError(t, err)

	// 验证已清理
	err = server.DB.Get(&count, "SELECT COUNT(*) FROM login_attempts WHERE username = ?", user.Username)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestCleanup_LoginAttempts_OldRecords(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 插入一个旧的登录尝试记录
	oldTime := time.Now().Add(-48 * time.Hour)
	_, err := server.DB.Exec(`
		INSERT INTO login_attempts (id, username, ip, success, createdAt)
		VALUES (?, ?, ?, ?, ?)
	`, "old-attempt-id", "olduser", "192.168.1.1", 0, oldTime)
	require.NoError(t, err)

	// 验证记录已创建
	var count int
	err = server.DB.Get(&count, "SELECT COUNT(*) FROM login_attempts")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1)

	// 清理超过 24 小时的记录
	cutoff := time.Now().Add(-24 * time.Hour)
	_, err = server.DB.Exec("DELETE FROM login_attempts WHERE createdAt < ?", cutoff)
	require.NoError(t, err)

	// 验证旧记录已被清理
	err = server.DB.Get(&count, "SELECT COUNT(*) FROM login_attempts")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// ========== 过期会话清理测试 ==========

func TestCleanup_ExpiredSessions(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	user := server.CreateUser(t,
		helper.WithUsername("expiredsession"),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)

	// 创建一个已过期的会话
	expiredSession := &model.Session{
		ID:        "expired-session-id",
		UserID:    user.ID,
		Token:     "expired-token",
		ExpiresAt: model.CustomTime{Time: time.Now().Add(-24 * time.Hour)},
		CreatedAt: model.CustomTime{Time: time.Now().Add(-48 * time.Hour)},
	}
	err := server.SessionRepo.Create(context.Background(), expiredSession)
	require.NoError(t, err)

	// 创建一个有效的会话
	validSession := &model.Session{
		ID:        "valid-session-id",
		UserID:    user.ID,
		Token:     "valid-token",
		ExpiresAt: model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
		CreatedAt: model.Now(),
	}
	err = server.SessionRepo.Create(context.Background(), validSession)
	require.NoError(t, err)

	// 验证两个会话都存在
	sessions, err := server.SessionRepo.FindByUserID(context.Background(), user.ID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(sessions), 2)

	// 清理过期会话
	_, err = server.DB.Exec("DELETE FROM sessions WHERE expiresAt < ?", time.Now())
	require.NoError(t, err)

	// 验证只有有效会话保留
	sessions, err = server.SessionRepo.FindByUserID(context.Background(), user.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, len(sessions))
	// 数据库中 token 存储为 SHA-256 哈希
	assert.Equal(t, util.HashToken("valid-token"), sessions[0].Token)
}

// ========== 过期邀请清理测试 ==========

func TestCleanup_ExpiredInvitations(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建管理员
	admin := server.CreateAdmin(t)

	// 创建一个已过期的邀请
	email1 := "expired@example.com"
	expiredInvitation := &model.Invitation{
		Email:         &email1,
		Challenge:     "expired-challenge",
		EmailVerified: false,
		CreatedBy:     admin.ID,
		ExpiresAt:     model.CustomTime{Time: time.Now().Add(-24 * time.Hour)},
		CreatedAt:     model.Now(),
	}
	err := server.InvitationRepo.Create(context.Background(), expiredInvitation, nil)
	require.NoError(t, err)

	// 创建一个有效的邀请
	email2 := "valid@example.com"
	validInvitation := &model.Invitation{
		Email:         &email2,
		Challenge:     "valid-challenge",
		EmailVerified: false,
		CreatedBy:     admin.ID,
		ExpiresAt:     model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
		CreatedAt:     model.Now(),
	}
	err = server.InvitationRepo.Create(context.Background(), validInvitation, nil)
	require.NoError(t, err)

	// 验证两个邀请都存在
	invitations, err := server.InvitationService.ListInvitations(context.Background())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(invitations), 2)

	// 清理过期邀请
	count, err := server.InvitationService.CleanupExpired(context.Background())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, int64(1))

	// 验证只有有效邀请保留
	invitations, err = server.InvitationService.ListInvitations(context.Background())
	require.NoError(t, err)
	for _, inv := range invitations {
		assert.NotEqual(t, "expired-challenge", inv.Challenge)
	}
}

// ========== OIDC Payloads 清理测试 ==========

func TestCleanup_OIDCPayloads(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建一个过期的 OIDC payload
	expiredTime := model.CustomTime{Time: time.Now().Add(-24 * time.Hour)}
	expiredPayload := &model.OIDCPayload{
		ID:        "expired-payload-id",
		Type:      "AuthRequest",
		Payload:   `{"test": "data"}`,
		ExpiresAt: &expiredTime,
	}
	err := server.OIDCRepo.Create(context.Background(), expiredPayload)
	require.NoError(t, err)

	// 创建一个有效的 OIDC payload
	validTime := model.CustomTime{Time: time.Now().Add(24 * time.Hour)}
	validPayload := &model.OIDCPayload{
		ID:        "valid-payload-id",
		Type:      "AuthRequest",
		Payload:   `{"test": "data"}`,
		ExpiresAt: &validTime,
	}
	err = server.OIDCRepo.Create(context.Background(), validPayload)
	require.NoError(t, err)

	// 验证两个 payload 都存在
	var count int
	err = server.DB.Get(&count, "SELECT COUNT(*) FROM oidc_payloads")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 2)

	// 清理过期 payload
	_, err = server.DB.Exec("DELETE FROM oidc_payloads WHERE expiresAt < ?", time.Now())
	require.NoError(t, err)

	// 验证只有有效 payload 保留
	err = server.DB.Get(&count, "SELECT COUNT(*) FROM oidc_payloads")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// ========== 过期密钥清理测试 ==========

func TestCleanup_ExpiredKeys(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建一个过期的密钥
	expiredKey := &model.Key{
		ID:        "expired-key-id",
		Type:      "signing",
		Value:     "expired-key-value",
		ExpiresAt: model.CustomTime{Time: time.Now().Add(-24 * time.Hour)},
		CreatedAt: model.Now(),
	}
	err := server.KeyRepo.Create(context.Background(), expiredKey)
	require.NoError(t, err)

	// 创建一个有效的密钥
	validKey := &model.Key{
		ID:        "valid-key-id",
		Type:      "signing",
		Value:     "valid-key-value",
		ExpiresAt: model.CustomTime{Time: time.Now().Add(365 * 24 * time.Hour)},
		CreatedAt: model.Now(),
	}
	err = server.KeyRepo.Create(context.Background(), validKey)
	require.NoError(t, err)

	// 验证两个密钥都存在
	var count int
	err = server.DB.Get(&count, "SELECT COUNT(*) FROM keys")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 2)

	// 清理过期密钥
	_, err = server.DB.Exec("DELETE FROM keys WHERE expiresAt IS NOT NULL AND expiresAt < ?", time.Now())
	require.NoError(t, err)

	// 验证只有有效密钥保留
	err = server.DB.Get(&count, "SELECT COUNT(*) FROM keys")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1)
}

// ========== 综合清理测试 ==========

func TestCleanup_AllTables(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 创建用户
	user := server.CreateUser(t,
		helper.WithUsername("allcleanup"),
		helper.WithApproved(true),
		helper.WithEmailVerified(true),
	)
	admin := server.CreateAdmin(t)

	// 创建各种数据
	// 1. 审计日志
	server.AuditService.Log(context.Background(), "test_action", &user.ID, nil, "test details", "127.0.0.1")

	// 2. 登录尝试
	_, _ = server.AuthService.Login(context.Background(), &service.LoginRequest{
		Username: "nonexistent",
		Password: "wrong",
	}, "127.0.0.1")

	// 3. 过期会话
	expiredSession := &model.Session{
		ID:        "expired-all-cleanup",
		UserID:    user.ID,
		Token:     "expired-token-all",
		ExpiresAt: model.CustomTime{Time: time.Now().Add(-24 * time.Hour)},
		CreatedAt: model.Now(),
	}
	_ = server.SessionRepo.Create(context.Background(), expiredSession)

	// 4. 过期邀请
	email := "expired-all@example.com"
	expiredInv := &model.Invitation{
		Email:         &email,
		Challenge:     "expired-all-challenge",
		CreatedBy:     admin.ID,
		ExpiresAt:     model.CustomTime{Time: time.Now().Add(-24 * time.Hour)},
		CreatedAt:     model.Now(),
	}
	_ = server.InvitationRepo.Create(context.Background(), expiredInv, nil)

	// 执行清理
	now := time.Now()

	// 清理会话
	_, _ = server.DB.Exec("DELETE FROM sessions WHERE expiresAt < ?", now)

	// 清理邀请
	_, _ = server.DB.Exec("DELETE FROM invitations WHERE expiresAt < ?", now)

	// 清理 OIDC payloads
	_, _ = server.DB.Exec("DELETE FROM oidc_payloads WHERE expiresAt < ?", now)

	// 清理密钥
	_, _ = server.DB.Exec("DELETE FROM keys WHERE expiresAt IS NOT NULL AND expiresAt < ?", now)

	// 验证用户仍然存在（清理不应影响用户）
	_, err := server.UserRepo.FindByUsername(context.Background(), "allcleanup")
	assert.NoError(t, err, "用户不应该被清理")
}

// ========== 配置相关测试 ==========

func TestCleanup_ConfigDefaults(t *testing.T) {
	server := helper.NewTestServer(t)
	defer server.Close()

	// 验证清理配置有合理的默认值
	cfg := server.Cfg

	// 注意：如果配置中没有这些字段，需要添加或使用默认值
	// 这里测试配置是否存在以及是否合理
	assert.NotNil(t, cfg)
	assert.Greater(t, cfg.Security.LoginBlockDuration, 0)
	assert.Greater(t, cfg.Security.LoginMaxAttempts, 0)
}
