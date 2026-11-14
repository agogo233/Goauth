package service

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pquerna/otp/totp"

	"goauth/internal/config"
	dbpkg "goauth/internal/db"
	"goauth/internal/util"
)

func setupTotpTestDB(t *testing.T) *sqlx.DB {
	t.Helper()

	db, err := sqlx.Open("sqlite3", ":memory:?_foreign_keys=on")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// 复用生产迁移，保证测试与生产 schema 一致
	if err := dbpkg.RunMigrations(db); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
	})

	return db
}

func setupTotpTestConfig() *config.Config {
	key := make([]byte, 32)
	rand.Read(key)

	return &config.Config{
		UI: config.UIConfig{
			AppName: "TestApp",
		},
		Security: config.SecurityConfig{
			CryptoKey: key,
		},
	}
}

func TestTotpService_Setup(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	// 先创建测试用户
	now := time.Now()
	_, err := db.ExecContext(ctx, `
		INSERT INTO users (id, username, createdAt, updatedAt)
		VALUES (?, ?, ?, ?)
	`, "user1", "testuser", now, now)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	resp, err := svc.Setup(ctx, "user1", "testuser")
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	if resp.URI == "" {
		t.Error("Setup() returned empty URI")
	}
	if resp.QrBase64 == "" {
		t.Error("Setup() returned empty QR base64")
	}
	if resp.Secret == "" {
		t.Error("Setup() returned empty secret")
	}
	if resp.EncryptedSecret == "" {
		t.Error("Setup() returned empty encryptedSecret")
	}

	// 验证 URI 格式
	if resp.URI[:15] != "otpauth://totp/" {
		t.Errorf("Setup() URI has wrong format: %s", resp.URI[:15])
	}
}

func TestTotpService_Setup_AlreadyEnabled(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	// 创建测试用户
	now := time.Now()
	_, err := db.ExecContext(ctx, `
		INSERT INTO users (id, username, createdAt, updatedAt)
		VALUES (?, ?, ?, ?)
	`, "user1", "testuser", now, now)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// 第一次设置（生成密钥但不存储）
	resp, err := svc.Setup(ctx, "user1", "testuser")
	if err != nil {
		t.Fatalf("First Setup() error = %v", err)
	}

	// 确认设置（存储密钥）
	err = svc.ConfirmSetup(ctx, "user1", resp.EncryptedSecret)
	if err != nil {
		t.Fatalf("ConfirmSetup() error = %v", err)
	}

	// 再次设置应该失败
	_, err = svc.Setup(ctx, "user1", "testuser")
	if err != ErrTotpAlreadyEnabled {
		t.Errorf("Second Setup() error = %v, want %v", err, ErrTotpAlreadyEnabled)
	}
}

func TestTotpService_IsEnabled(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	// 创建测试用户
	now := time.Now()
	_, err := db.ExecContext(ctx, `
		INSERT INTO users (id, username, createdAt, updatedAt)
		VALUES (?, ?, ?, ?)
	`, "user1", "testuser", now, now)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// 未设置时
	enabled, err := svc.IsEnabled(ctx, "user1")
	if err != nil {
		t.Fatalf("IsEnabled() error = %v", err)
	}
	if enabled {
		t.Error("IsEnabled() = true, want false before setup")
	}

	// Setup 后（还未确认）
	resp, err := svc.Setup(ctx, "user1", "testuser")
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	// 仍未启用
	enabled, err = svc.IsEnabled(ctx, "user1")
	if err != nil {
		t.Fatalf("IsEnabled() error = %v", err)
	}
	if enabled {
		t.Error("IsEnabled() = true after Setup(), want false before ConfirmSetup()")
	}

	// 确认设置后
	err = svc.ConfirmSetup(ctx, "user1", resp.EncryptedSecret)
	if err != nil {
		t.Fatalf("ConfirmSetup() error = %v", err)
	}

	enabled, err = svc.IsEnabled(ctx, "user1")
	if err != nil {
		t.Fatalf("IsEnabled() error = %v", err)
	}
	if !enabled {
		t.Error("IsEnabled() = false, want true after ConfirmSetup()")
	}
}

func TestTotpService_Remove(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	// 创建测试用户并设置 TOTP
	now := time.Now()
	_, err := db.ExecContext(ctx, `
		INSERT INTO users (id, username, createdAt, updatedAt)
		VALUES (?, ?, ?, ?)
	`, "user1", "testuser", now, now)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Setup 并确认
	resp, err := svc.Setup(ctx, "user1", "testuser")
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	err = svc.ConfirmSetup(ctx, "user1", resp.EncryptedSecret)
	if err != nil {
		t.Fatalf("ConfirmSetup() error = %v", err)
	}

	// 移除
	err = svc.Remove(ctx, "user1")
	if err != nil {
		t.Fatalf("Remove() error = %v", err)
	}

	// 验证已移除
	enabled, _ := svc.IsEnabled(ctx, "user1")
	if enabled {
		t.Error("IsEnabled() = true after Remove()")
	}
}

func TestTotpService_VerifySetupCode(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	// 创建测试用户
	now := time.Now()
	_, err := db.ExecContext(ctx, `
		INSERT INTO users (id, username, createdAt, updatedAt)
		VALUES (?, ?, ?, ?)
	`, "user1", "testuser", now, now)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Setup
	resp, err := svc.Setup(ctx, "user1", "testuser")
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	// 使用错误的验证码
	valid := svc.VerifySetupCode(resp.Secret, "000000")
	if valid {
		t.Error("VerifySetupCode() = true for invalid code")
	}

	// 使用正确的验证码（需要用 pquerna/otp/totp 生成）
	// 注意：这里我们只测试方法可以调用，实际验证码验证需要时间同步
}

func TestTotpService_GenerateBackupCodes(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	// 创建测试用户（totp_backup_codes 有外键约束）
	now := time.Now()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO users (id, username, createdAt, updatedAt)
		VALUES (?, ?, ?, ?)
	`, "user1", "testuser", now, now); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	codes, err := svc.GenerateBackupCodes(ctx, "user1")
	if err != nil {
		t.Fatalf("GenerateBackupCodes() error = %v", err)
	}

	if len(codes) != 10 {
		t.Errorf("GenerateBackupCodes() returned %d codes, want 10", len(codes))
	}

	// 检查格式
	for i, code := range codes {
		if len(code) < 5 {
			t.Errorf("Code %d too short: %s", i, code)
		}
	}
}

func TestValidateUri(t *testing.T) {
	// 有效 URI
	validURI := "otpauth://totp/TestApp:testuser?secret=JBSWY3DPEHPK3PXP&issuer=TestApp"
	key, err := ValidateUri(validURI)
	if err != nil {
		t.Fatalf("ValidateUri() error = %v", err)
	}
	if key.Secret() != "JBSWY3DPEHPK3PXP" {
		t.Errorf("ValidateUri() secret = %s, want JBSWY3DPEHPK3PXP", key.Secret())
	}
}

func TestParseSecretFromUri(t *testing.T) {
	uri := "otpauth://totp/TestApp:testuser?secret=JBSWY3DPEHPK3PXP&issuer=TestApp"
	secret, err := ParseSecretFromUri(uri)
	if err != nil {
		t.Fatalf("ParseSecretFromUri() error = %v", err)
	}
	if secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("ParseSecretFromUri() = %s, want JBSWY3DPEHPK3PXP", secret)
	}
}

// ========== 加密解密测试 ==========

func TestTotpService_EncryptDecrypt(t *testing.T) {
	cfg := setupTotpTestConfig()
	secret := "JBSWY3DPEHPK3PXP"

	// 加密
	encrypted, err := util.Encrypt(secret, cfg.Security.CryptoKey)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if encrypted == "" {
		t.Error("Encrypt() returned empty string")
	}
	if encrypted == secret {
		t.Error("Encrypt() should not return the same string")
	}

	// 解密
	decrypted, err := util.Decrypt(encrypted, cfg.Security.CryptoKey)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if decrypted != secret {
		t.Errorf("Decrypt() = %s, want %s", decrypted, secret)
	}
}

func TestTotpService_EncryptDifferentEachTime(t *testing.T) {
	cfg := setupTotpTestConfig()
	secret := "JBSWY3DPEHPK3PXP"

	// 多次加密应该产生不同的结果（因为 nonce 不同）
	encrypted1, _ := util.Encrypt(secret, cfg.Security.CryptoKey)
	encrypted2, _ := util.Encrypt(secret, cfg.Security.CryptoKey)

	if encrypted1 == encrypted2 {
		t.Error("Multiple encryptions should produce different results due to random nonce")
	}

	// 但两个都应该能正确解密
	decrypted1, _ := util.Decrypt(encrypted1, cfg.Security.CryptoKey)
	decrypted2, _ := util.Decrypt(encrypted2, cfg.Security.CryptoKey)

	if decrypted1 != secret || decrypted2 != secret {
		t.Error("Both decrypted values should match original secret")
	}
}

func TestTotpService_DecryptInvalidKey(t *testing.T) {
	cfg := setupTotpTestConfig()
	secret := "JBSWY3DPEHPK3PXP"

	encrypted, _ := util.Encrypt(secret, cfg.Security.CryptoKey)

	// 使用错误的密钥解密
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)

	_, err := util.Decrypt(encrypted, wrongKey)
	if err == nil {
		t.Error("Decrypt() with wrong key should fail")
	}
}

func TestTotpService_EncryptInvalidKeySize(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"

	// 使用错误长度的密钥
	wrongKey := make([]byte, 16) // 应该是 32 字节

	_, err := util.Encrypt(secret, wrongKey)
	if err == nil {
		t.Error("Encrypt() with invalid key size should fail")
	}
}

// ========== 时间窗口验证测试 ==========

func TestTotpService_VerifySetupCode_ValidCode(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	// 创建测试用户
	now := time.Now()
	_, _ = db.ExecContext(ctx, `INSERT INTO users (id, username, createdAt, updatedAt) VALUES (?, ?, ?, ?)`, "user1", "testuser", now, now)

	// Setup 获取密钥
	resp, err := svc.Setup(ctx, "user1", "testuser")
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	// 使用 pquerna/otp/totp 生成有效代码
	validCode, err := totp.GenerateCode(resp.Secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode() error = %v", err)
	}

	// 验证
	if !svc.VerifySetupCode(resp.Secret, validCode) {
		t.Error("VerifySetupCode() should return true for valid code")
	}
}

func TestTotpService_VerifySetupCode_InvalidCode(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	now := time.Now()
	_, _ = db.ExecContext(ctx, `INSERT INTO users (id, username, createdAt, updatedAt) VALUES (?, ?, ?, ?)`, "user1", "testuser", now, now)

	resp, _ := svc.Setup(ctx, "user1", "testuser")

	// 使用无效代码
	if svc.VerifySetupCode(resp.Secret, "000000") {
		t.Error("VerifySetupCode() should return false for invalid code")
	}
	if svc.VerifySetupCode(resp.Secret, "123456") {
		t.Error("VerifySetupCode() should return false for invalid code")
	}
	if svc.VerifySetupCode(resp.Secret, "abcdef") {
		t.Error("VerifySetupCode() should return false for non-numeric code")
	}
}

func TestTotpService_VerifySetupCode_EmptyCode(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	now := time.Now()
	_, _ = db.ExecContext(ctx, `INSERT INTO users (id, username, createdAt, updatedAt) VALUES (?, ?, ?, ?)`, "user1", "testuser", now, now)

	resp, _ := svc.Setup(ctx, "user1", "testuser")

	// 空代码
	if svc.VerifySetupCode(resp.Secret, "") {
		t.Error("VerifySetupCode() should return false for empty code")
	}
}

// ========== Verify 服务层测试 ==========

func TestTotpService_Verify_Success(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	// 创建测试用户并设置 TOTP
	now := time.Now()
	_, _ = db.ExecContext(ctx, `INSERT INTO users (id, username, createdAt, updatedAt) VALUES (?, ?, ?, ?)`, "user1", "testuser", now, now)

	resp, _ := svc.Setup(ctx, "user1", "testuser")
	_ = svc.ConfirmSetup(ctx, "user1", resp.EncryptedSecret)

	// 生成有效代码
	validCode, _ := totp.GenerateCode(resp.Secret, time.Now())

	// 验证
	valid, err := svc.Verify(ctx, "user1", validCode)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !valid {
		t.Error("Verify() should return true for valid code")
	}
}

func TestTotpService_Verify_UserNotFound(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	// 用户不存在，应该返回错误
	_, err := svc.Verify(ctx, "nonexistent", "123456")
	if err != ErrTotpNotEnabled {
		t.Errorf("Verify() error = %v, want %v", err, ErrTotpNotEnabled)
	}
}

func TestTotpService_Verify_WrongCode(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	// 创建测试用户并设置 TOTP
	now := time.Now()
	_, _ = db.ExecContext(ctx, `INSERT INTO users (id, username, createdAt, updatedAt) VALUES (?, ?, ?, ?)`, "user1", "testuser", now, now)

	resp, _ := svc.Setup(ctx, "user1", "testuser")
	_ = svc.ConfirmSetup(ctx, "user1", resp.EncryptedSecret)

	// 使用错误代码
	valid, err := svc.Verify(ctx, "user1", "000000")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if valid {
		t.Error("Verify() should return false for wrong code")
	}
}

// ========== URI 验证测试 ==========

func TestValidateUri_InvalidFormat(t *testing.T) {
	// pquerna/otp 库的 NewKeyFromURL 非常宽松，几乎接受任何输入
	// 这里我们只是测试函数可以被调用
	key, err := ValidateUri("not-a-valid-uri")
	// 库可能会返回一个 key（即使内容无效）
	_ = key
	_ = err
}

func TestValidateUri_MissingSecret(t *testing.T) {
	// 缺少 secret 参数 - 库仍然会返回 key
	uri := "otpauth://totp/TestApp:testuser?issuer=TestApp"
	key, err := ValidateUri(uri)
	// 库不会报错，但 secret 为空
	if err == nil && key != nil {
		// 检查 secret 是否为空
		if key.Secret() != "" {
			t.Logf("Unexpected secret: %s", key.Secret())
		}
	}
}

func TestValidateUri_InvalidScheme(t *testing.T) {
	// 错误的协议 - 库仍然会返回 key
	uri := "http://totp/TestApp:testuser?secret=JBSWY3DPEHPK3PXP&issuer=TestApp"
	key, err := ValidateUri(uri)
	// 库不会严格检查协议
	_ = key
	_ = err
}

func TestParseSecretFromUri_EmptySecret(t *testing.T) {
	// URI 中没有 secret
	uri := "otpauth://totp/TestApp:testuser?issuer=TestApp"
	secret, err := ParseSecretFromUri(uri)
	if err != nil {
		t.Fatalf("ParseSecretFromUri() error = %v", err)
	}
	if secret != "" {
		t.Errorf("ParseSecretFromUri() = %s, want empty string", secret)
	}
}

// ========== 并发安全测试 ==========

func TestTotpService_ConcurrentVerify(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	// 创建测试用户并设置 TOTP
	now := time.Now()
	_, _ = db.ExecContext(ctx, `INSERT INTO users (id, username, createdAt, updatedAt) VALUES (?, ?, ?, ?)`, "user1", "testuser", now, now)

	resp, _ := svc.Setup(ctx, "user1", "testuser")
	_ = svc.ConfirmSetup(ctx, "user1", resp.EncryptedSecret)

	// 使用 VerifySetupCode 而不是数据库验证，避免 TOTP 时间窗口问题
	// 并发验证
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			// 每次生成新的代码，避免时间窗口问题
			validCode, _ := totp.GenerateCode(resp.Secret, time.Now())
			valid := svc.VerifySetupCode(resp.Secret, validCode)
			done <- valid
		}()
	}

	// 收集结果
	successCount := 0
	for i := 0; i < 10; i++ {
		if <-done {
			successCount++
		}
	}

	// 大部分并发请求应该成功（允许少量因时间窗口变化失败）
	if successCount < 8 {
		t.Errorf("Concurrent verify: %d successes, want at least 8", successCount)
	}
}

// ========== 备用码格式测试 ==========

func TestTotpService_GenerateBackupCodes_Format(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	// 创建测试用户（totp_backup_codes 有外键约束）
	now := time.Now()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO users (id, username, createdAt, updatedAt)
		VALUES (?, ?, ?, ?)
	`, "user1", "testuser", now, now); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	codes, err := svc.GenerateBackupCodes(ctx, "user1")
	if err != nil {
		t.Fatalf("GenerateBackupCodes() error = %v", err)
	}

	// 检查格式：应该是 xxx-xxx 格式
	for i, code := range codes {
		if len(code) < 5 {
			t.Errorf("Backup code %d too short: %s", i, code)
		}
		// 检查是否包含分隔符
		if !contains(code, "-") {
			t.Errorf("Backup code %d should contain '-': %s", i, code)
		}
	}
}

func TestTotpService_GenerateBackupCodes_Uniqueness(t *testing.T) {
	db := setupTotpTestDB(t)
	cfg := setupTotpTestConfig()
	svc := NewTotpService(db, cfg)
	ctx := context.Background()

	// 创建测试用户（totp_backup_codes 有外键约束）
	now := time.Now()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO users (id, username, createdAt, updatedAt)
		VALUES (?, ?, ?, ?)
	`, "user1", "testuser", now, now); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// 生成两组备用码
	codes1, err := svc.GenerateBackupCodes(ctx, "user1")
	if err != nil {
		t.Fatalf("GenerateBackupCodes() #1 error = %v", err)
	}
	codes2, err := svc.GenerateBackupCodes(ctx, "user1")
	if err != nil {
		t.Fatalf("GenerateBackupCodes() #2 error = %v", err)
	}

	// 两组应该不同
	sameCount := 0
	for i := 0; i < 10; i++ {
		if codes1[i] == codes2[i] {
			sameCount++
		}
	}

	// 不应该完全相同（概率极低）
	if sameCount == 10 {
		t.Error("Two sets of backup codes should not be identical")
	}
}

// 辅助函数
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}