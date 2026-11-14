package repo

import (
	"context"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"

	"goauth/internal/model"
	"goauth/internal/util"
)

func setupSessionTestDB(t *testing.T) *sqlx.DB {
	t.Helper()

	db, err := sqlx.Open("sqlite3", ":memory:?_foreign_keys=on")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

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
	`
	_, err = db.Exec(schema)
	if err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
	})

	return db
}

func createTestUserForSession(db *sqlx.DB, ctx context.Context, id, username string) error {
	now := time.Now()
	_, err := db.ExecContext(ctx, `
		INSERT INTO users (id, username, createdAt, updatedAt)
		VALUES (?, ?, ?, ?)
	`, id, username, now, now)
	return err
}

func TestSessionRepo_Create(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepo(db)
	ctx := context.Background()

	createTestUserForSession(db, ctx, "user1", "testuser")

	session := &model.Session{
		UserID:     "user1",
		Token:      "test-token-123",
		AMR:        "pwd",
		RememberMe: false,
		ExpiresAt:  model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
	}

	err := repo.Create(ctx, session)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if session.ID == "" {
		t.Error("Create() did not set session ID")
	}
}

func TestSessionRepo_FindByToken(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepo(db)
	ctx := context.Background()

	createTestUserForSession(db, ctx, "user1", "testuser")

	session := &model.Session{
		UserID:     "user1",
		Token:      "test-token-123",
		AMR:        "pwd",
		ExpiresAt:  model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
	}
	repo.Create(ctx, session)

	found, err := repo.FindByToken(ctx, "test-token-123")
	if err != nil {
		t.Fatalf("FindByToken() error = %v", err)
	}
	if found.ID != session.ID {
		t.Errorf("FindByToken() ID = %s, want %s", found.ID, session.ID)
	}
}

func TestSessionRepo_FindByToken_NotFound(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepo(db)
	ctx := context.Background()

	_, err := repo.FindByToken(ctx, "nonexistent-token")
	if err != ErrSessionNotFound {
		t.Errorf("FindByToken() error = %v, want %v", err, ErrSessionNotFound)
	}
}

func TestSessionRepo_FindByID(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepo(db)
	ctx := context.Background()

	createTestUserForSession(db, ctx, "user1", "testuser")

	session := &model.Session{
		UserID:     "user1",
		Token:      "test-token-123",
		AMR:        "pwd",
		ExpiresAt:  model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
	}
	repo.Create(ctx, session)

	found, err := repo.FindByID(ctx, session.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	// 数据库存储的是 token 的 SHA-256 哈希，FindByID 返回哈希值
	if found.Token != util.HashToken(session.Token) {
		t.Errorf("FindByID() token = %s, want hash of %s", found.Token, session.Token)
	}
}

func TestSessionRepo_FindByID_NotFound(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepo(db)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, "nonexistent-id")
	if err != ErrSessionNotFound {
		t.Errorf("FindByID() error = %v, want %v", err, ErrSessionNotFound)
	}
}

func TestSessionRepo_FindByUserID(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepo(db)
	ctx := context.Background()

	createTestUserForSession(db, ctx, "user1", "testuser")

	// 创建多个会话
	for i := 0; i < 3; i++ {
		session := &model.Session{
			UserID:     "user1",
			Token:      "token-" + string(rune('0'+i)),
			AMR:        "pwd",
			ExpiresAt:  model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
		}
		repo.Create(ctx, session)
		time.Sleep(time.Millisecond)
	}

	sessions, err := repo.FindByUserID(ctx, "user1")
	if err != nil {
		t.Fatalf("FindByUserID() error = %v", err)
	}
	if len(sessions) != 3 {
		t.Errorf("FindByUserID() returned %d sessions, want 3", len(sessions))
	}
}

func TestSessionRepo_Delete(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepo(db)
	ctx := context.Background()

	createTestUserForSession(db, ctx, "user1", "testuser")

	session := &model.Session{
		UserID:     "user1",
		Token:      "test-token-123",
		AMR:        "pwd",
		ExpiresAt:  model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
	}
	repo.Create(ctx, session)

	err := repo.Delete(ctx, session.ID)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err = repo.FindByID(ctx, session.ID)
	if err != ErrSessionNotFound {
		t.Errorf("Delete() session still exists, error = %v", err)
	}
}

func TestSessionRepo_DeleteByToken(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepo(db)
	ctx := context.Background()

	createTestUserForSession(db, ctx, "user1", "testuser")

	session := &model.Session{
		UserID:     "user1",
		Token:      "test-token-123",
		AMR:        "pwd",
		ExpiresAt:  model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
	}
	repo.Create(ctx, session)

	err := repo.DeleteByToken(ctx, "test-token-123")
	if err != nil {
		t.Fatalf("DeleteByToken() error = %v", err)
	}

	_, err = repo.FindByToken(ctx, "test-token-123")
	if err != ErrSessionNotFound {
		t.Errorf("DeleteByToken() session still exists, error = %v", err)
	}
}

func TestSessionRepo_DeleteByUserID(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepo(db)
	ctx := context.Background()

	createTestUserForSession(db, ctx, "user1", "testuser")
	createTestUserForSession(db, ctx, "user2", "testuser2")

	// 创建多个会话
	for i := 0; i < 3; i++ {
		session := &model.Session{
			UserID:     "user1",
			Token:      "user1-token-" + string(rune('0'+i)),
			AMR:        "pwd",
			ExpiresAt:  model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
		}
		repo.Create(ctx, session)
	}

	session := &model.Session{
		UserID:     "user2",
		Token:      "user2-token",
		AMR:        "pwd",
		ExpiresAt:  model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
	}
	repo.Create(ctx, session)

	// 删除 user1 的所有会话
	err := repo.DeleteByUserID(ctx, "user1")
	if err != nil {
		t.Fatalf("DeleteByUserID() error = %v", err)
	}

	// 验证 user1 的会话已删除
	sessions, _ := repo.FindByUserID(ctx, "user1")
	if len(sessions) != 0 {
		t.Errorf("DeleteByUserID() user1 has %d sessions, want 0", len(sessions))
	}

	// 验证 user2 的会话还在
	sessions, _ = repo.FindByUserID(ctx, "user2")
	if len(sessions) != 1 {
		t.Errorf("DeleteByUserID() user2 has %d sessions, want 1", len(sessions))
	}
}

func TestSessionRepo_DeleteExpired(t *testing.T) {
	db := setupSessionTestDB(t)
	repo := NewSessionRepo(db)
	ctx := context.Background()

	createTestUserForSession(db, ctx, "user1", "testuser")

	// 创建过期会话
	expiredSession := &model.Session{
		UserID:     "user1",
		Token:      "expired-token",
		AMR:        "pwd",
		ExpiresAt:  model.CustomTime{Time: time.Now().Add(-1 * time.Hour)}, // 已过期
	}
	repo.Create(ctx, expiredSession)

	// 创建有效会话
	validSession := &model.Session{
		UserID:     "user1",
		Token:      "valid-token",
		AMR:        "pwd",
		ExpiresAt:  model.CustomTime{Time: time.Now().Add(24 * time.Hour)},
	}
	repo.Create(ctx, validSession)

	// 删除过期会话
	err := repo.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired() error = %v", err)
	}

	// 验证过期会话已删除
	_, err = repo.FindByToken(ctx, "expired-token")
	if err != ErrSessionNotFound {
		t.Errorf("DeleteExpired() expired session still exists")
	}

	// 验证有效会话还在
	_, err = repo.FindByToken(ctx, "valid-token")
	if err != nil {
		t.Errorf("DeleteExpired() valid session was deleted")
	}
}
