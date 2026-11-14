package util

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) *sqlx.DB {
	t.Helper()

	// 创建临时数据库
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	dsn := dbPath + "?_journal_mode=MEMORY&_foreign_keys=on"
	db, err := sqlx.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// 创建 login_attempts 表
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS login_attempts (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			ip TEXT NOT NULL,
			success INTEGER DEFAULT 0,
			createdAt TEXT NOT NULL
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create login_attempts table: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
	})

	return db
}

func TestBruteForceProtector_RecordAttempt(t *testing.T) {
	db := setupTestDB(t)
	protector := NewBruteForceProtector(db, 5, 30, 5)
	ctx := context.Background()

	tests := []struct {
		name     string
		username string
		ip       string
		success  bool
	}{
		{"成功登录", "user1", "192.168.1.1", true},
		{"失败登录", "user1", "192.168.1.1", false},
		{"另一个用户", "user2", "192.168.1.2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protector.RecordAttempt(ctx, tt.username, tt.ip, tt.success)
			if err != nil {
				t.Errorf("RecordAttempt() error = %v", err)
			}
		})
	}
}

func TestBruteForceProtector_IsBlocked(t *testing.T) {
	db := setupTestDB(t)
	protector := NewBruteForceProtector(db, 3, 30, 3) // 3次失败后封锁
	ctx := context.Background()

	// 记录失败尝试（同一 IP）
	for i := 0; i < 3; i++ {
		err := protector.RecordAttempt(ctx, "blocked_user", "192.168.1.1", false)
		if err != nil {
			t.Fatalf("RecordAttempt() error = %v", err)
		}
	}

	// 检查该 IP 是否被封锁
	blocked, err := protector.IsBlocked(ctx, "blocked_user", "192.168.1.1")
	if err != nil {
		t.Fatalf("IsBlocked() error = %v", err)
	}

	if !blocked {
		t.Error("IsBlocked() = false, want true after 3 failed attempts from same IP")
	}

	// 检查另一个 IP 是否未被封锁
	blocked, err = protector.IsBlocked(ctx, "other_user", "192.168.1.2")
	if err != nil {
		t.Fatalf("IsBlocked() error = %v", err)
	}

	if blocked {
		t.Error("IsBlocked() = true for IP with no failed attempts")
	}

	// 关键测试：同一 IP 尝试封锁其他用户名不应成功
	// 即使用户名不同，只要 IP 不同就不应受影响
	blocked, err = protector.IsBlocked(ctx, "different_user", "192.168.1.1")
	if err != nil {
		t.Fatalf("IsBlocked() error = %v", err)
	}

	if !blocked {
		t.Error("IsBlocked() = false, IP should be blocked regardless of username")
	}
}

func TestBruteForceProtector_IsBlocked_ByIP(t *testing.T) {
	db := setupTestDB(t)
	protector := NewBruteForceProtector(db, 3, 30, 3) // 3次失败后封锁 IP
	ctx := context.Background()

	// 同一 IP 多次失败（不同用户名）
	for i := 0; i < 3; i++ {
		err := protector.RecordAttempt(ctx, "user"+string(rune('0'+i)), "192.168.1.100", false)
		if err != nil {
			t.Fatalf("RecordAttempt() error = %v", err)
		}
	}

	// 检查该 IP 是否被封锁（即使使用不同用户名）
	blocked, err := protector.IsBlocked(ctx, "new_user", "192.168.1.100")
	if err != nil {
		t.Fatalf("IsBlocked() error = %v", err)
	}

	if !blocked {
		t.Error("IsBlocked() = false, want true after 3 IP-wide failed attempts")
	}

	// 验证其他 IP 不受影响
	blocked, err = protector.IsBlocked(ctx, "any_user", "192.168.1.200")
	if err != nil {
		t.Fatalf("IsBlocked() error = %v", err)
	}

	if blocked {
		t.Error("IsBlocked() = true for different IP")
	}
}

func TestBruteForceProtector_ClearAttempts(t *testing.T) {
	db := setupTestDB(t)
	protector := NewBruteForceProtector(db, 3, 30, 3)
	ctx := context.Background()

	// 记录失败尝试
	for i := 0; i < 3; i++ {
		protector.RecordAttempt(ctx, "clear_user", "192.168.1.1", false)
	}

	// 清除尝试记录
	err := protector.ClearAttempts(ctx, "clear_user")
	if err != nil {
		t.Fatalf("ClearAttempts() error = %v", err)
	}

	// 检查是否解除封锁
	blocked, err := protector.IsBlocked(ctx, "clear_user", "192.168.1.1")
	if err != nil {
		t.Fatalf("IsBlocked() error = %v", err)
	}

	if blocked {
		t.Error("IsBlocked() = true after ClearAttempts()")
	}
}

func TestBruteForceProtector_GetRemainingAttempts(t *testing.T) {
	db := setupTestDB(t)
	protector := NewBruteForceProtector(db, 5, 30, 5)
	ctx := context.Background()

	// 初始应该有 5 次剩余
	remaining, err := protector.GetRemainingAttempts(ctx, "192.168.1.1")
	if err != nil {
		t.Fatalf("GetRemainingAttempts() error = %v", err)
	}

	if remaining != 5 {
		t.Errorf("GetRemainingAttempts() = %v, want 5", remaining)
	}

	// 记录 2 次失败（同一 IP）
	protector.RecordAttempt(ctx, "test_user", "192.168.1.1", false)
	protector.RecordAttempt(ctx, "test_user", "192.168.1.1", false)

	remaining, err = protector.GetRemainingAttempts(ctx, "192.168.1.1")
	if err != nil {
		t.Fatalf("GetRemainingAttempts() error = %v", err)
	}

	if remaining != 3 {
		t.Errorf("GetRemainingAttempts() = %v, want 3", remaining)
	}

	// 记录成功登录不应该影响失败计数
	protector.RecordAttempt(ctx, "test_user", "192.168.1.1", true)

	remaining, err = protector.GetRemainingAttempts(ctx, "192.168.1.1")
	if err != nil {
		t.Fatalf("GetRemainingAttempts() error = %v", err)
	}

	if remaining != 3 {
		t.Errorf("GetRemainingAttempts() = %v, want 3 (success doesn't reduce failed count)", remaining)
	}

	// 验证其他 IP 不受影响
	remaining, err = protector.GetRemainingAttempts(ctx, "192.168.1.2")
	if err != nil {
		t.Fatalf("GetRemainingAttempts() error = %v", err)
	}

	if remaining != 5 {
		t.Errorf("GetRemainingAttempts() = %v for different IP, want 5", remaining)
	}
}

func TestBruteForceProtector_CleanupOldAttempts(t *testing.T) {
	db := setupTestDB(t)
	protector := NewBruteForceProtector(db, 5, 30, 5)
	ctx := context.Background()

	// 插入一条旧记录（手动插入以模拟过期）
	oldTime := time.Now().Add(-48 * time.Hour)
	_, err := db.ExecContext(ctx, `
		INSERT INTO login_attempts (id, username, ip, success, createdAt)
		VALUES ('old-id', 'old_user', '192.168.1.1', 0, ?)
	`, oldTime)
	if err != nil {
		t.Fatalf("Failed to insert old record: %v", err)
	}

	// 插入一条新记录
	protector.RecordAttempt(ctx, "new_user", "192.168.1.1", false)

	// 清理1天前的记录
	err = protector.CleanupOldAttempts(ctx, 1)
	if err != nil {
		t.Fatalf("CleanupOldAttempts() error = %v", err)
	}

	// 验证旧记录被删除
	var count int
	err = db.GetContext(ctx, &count, `SELECT COUNT(*) FROM login_attempts WHERE username = 'old_user'`)
	if err != nil {
		t.Fatalf("Failed to count records: %v", err)
	}

	if count != 0 {
		t.Error("Old record was not cleaned up")
	}

	// 验证新记录还在
	err = db.GetContext(ctx, &count, `SELECT COUNT(*) FROM login_attempts WHERE username = 'new_user'`)
	if err != nil {
		t.Fatalf("Failed to count records: %v", err)
	}

	if count != 1 {
		t.Error("New record was incorrectly cleaned up")
	}
}

func TestBruteForceProtector_SuccessfulLoginClearsBlocking(t *testing.T) {
	db := setupTestDB(t)
	protector := NewBruteForceProtector(db, 3, 30, 3)
	ctx := context.Background()

	// 记录 2 次失败（未达封锁阈值）
	protector.RecordAttempt(ctx, "partial_user", "192.168.1.1", false)
	protector.RecordAttempt(ctx, "partial_user", "192.168.1.1", false)

	blocked, _ := protector.IsBlocked(ctx, "partial_user", "192.168.1.1")
	if blocked {
		t.Error("IP should not be blocked after only 2 attempts")
	}

	// 成功登录后清除记录
	protector.ClearAttempts(ctx, "partial_user")

	// 再次检查剩余次数
	remaining, _ := protector.GetRemainingAttempts(ctx, "192.168.1.1")
	if remaining != 3 {
		t.Errorf("After clear, remaining attempts should be 3, got %d", remaining)
	}
}
