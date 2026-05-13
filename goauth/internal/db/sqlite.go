package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"

	"goauth/internal/config"
)

type DB struct {
	*sqlx.DB
}

func New(cfg *config.DatabaseConfig) (*DB, error) {
	// Ensure directory exists
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Open database with WAL mode for better concurrency
	// _loc=Asia/Shanghai: Parse time columns using Shanghai timezone
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on&_loc=Asia%%2fShanghai", cfg.Path)
	db, err := sqlx.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Info().Str("path", cfg.Path).Msg("Database connected")

	return &DB{db}, nil
}

func (db *DB) Close() error {
	return db.DB.Close()
}

func (db *DB) Transaction(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(tx.Tx); err != nil {
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (db *DB) RunMigrations() error {
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

		// Sessions table with lastRefreshedAt (v0.0.2)
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			userId TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			amr TEXT,
			rememberMe INTEGER DEFAULT 0,
			expiresAt TEXT NOT NULL,
			createdAt TEXT NOT NULL,
			lastRefreshedAt TEXT,
			totpAttempts INTEGER DEFAULT 0,
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

		// Keys table
		`CREATE TABLE IF NOT EXISTS keys (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			value TEXT NOT NULL,
			expiresAt TEXT NOT NULL,
			createdAt TEXT NOT NULL
		)`,

		// OIDC Payloads table
		`CREATE TABLE IF NOT EXISTS oidc_payloads (
			id TEXT NOT NULL,
			type TEXT NOT NULL,
			payload TEXT NOT NULL,
			grantId TEXT,
			userCode TEXT,
			uid TEXT,
			expiresAt TEXT,
			consumedAt TEXT,
			accountId TEXT,
			PRIMARY KEY (id, type)
		)`,

		// Clients table
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

		// TOTP Backup Codes table (v0.0.2)
		`CREATE TABLE IF NOT EXISTS totp_backup_codes (
			userId TEXT PRIMARY KEY NOT NULL,
			codesHash TEXT NOT NULL,
			createdAt TEXT NOT NULL,
			FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
		)`,

		// Consent table
		`CREATE TABLE IF NOT EXISTS consent (
			userId TEXT NOT NULL,
			clientId TEXT NOT NULL,
			scope TEXT NOT NULL,
			createdAt TEXT NOT NULL,
			expiresAt TEXT NOT NULL,
			PRIMARY KEY (userId, clientId),
			FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
		)`,

		// Invitations table
		`CREATE TABLE IF NOT EXISTS invitations (
			id TEXT PRIMARY KEY,
			email TEXT,
			username TEXT,
			name TEXT,
			challenge TEXT NOT NULL,
			emailVerified INTEGER DEFAULT 0,
			createdBy TEXT NOT NULL,
			createdAt TEXT NOT NULL,
			expiresAt TEXT NOT NULL,
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

		// Flags table
		`CREATE TABLE IF NOT EXISTS flags (
			name TEXT PRIMARY KEY,
			value TEXT,
			createdAt TEXT NOT NULL
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
			createdAt TEXT NOT NULL,
			FOREIGN KEY (actorId) REFERENCES users(id) ON DELETE SET NULL
		)`,

		// Indexes
		`CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_userId ON sessions(userId)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expiresAt ON sessions(expiresAt)`,
		`CREATE INDEX IF NOT EXISTS idx_oidc_payloads_expiresAt ON oidc_payloads(expiresAt)`,
		`CREATE INDEX IF NOT EXISTS idx_oidc_payloads_accountId ON oidc_payloads(accountId)`,
		`CREATE INDEX IF NOT EXISTS idx_oidc_payloads_grantId ON oidc_payloads(grantId)`,
		`CREATE INDEX IF NOT EXISTS idx_oidc_payloads_uid ON oidc_payloads(uid)`,
		`CREATE INDEX IF NOT EXISTS idx_users_approved ON users(approved)`,
		`CREATE INDEX IF NOT EXISTS idx_users_disabled ON users(disabled)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_createdAt ON login_attempts(createdAt)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_createdAt ON audit_log(createdAt)`,
		`CREATE INDEX IF NOT EXISTS idx_keys_expiresAt ON keys(expiresAt)`,

		// 额外性能优化索引
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
		`CREATE INDEX IF NOT EXISTS idx_invitations_expiresAt ON invitations(expiresAt)`,
		`CREATE INDEX IF NOT EXISTS idx_consent_expiresAt ON consent(expiresAt)`,
		`CREATE INDEX IF NOT EXISTS idx_user_groups_groupId ON user_groups(groupId)`,
		`CREATE INDEX IF NOT EXISTS idx_proxy_auth_groups_groupId ON proxy_auth_groups(groupId)`,
	}

	for i, migration := range migrations {
		if _, err := db.Exec(migration); err != nil {
			return fmt.Errorf("migration %d failed: %w", i, err)
		}
	}

	// Safe column additions (ignore "duplicate column" errors)
	alterStatements := []string{
		`ALTER TABLE sessions ADD COLUMN totpAttempts INTEGER DEFAULT 0`,
	}
	for _, stmt := range alterStatements {
		if _, err := db.Exec(stmt); err != nil {
			// Ignore "duplicate column name" errors
			if !isDuplicateColumnError(err) {
				return fmt.Errorf("alter table failed: %w", err)
			}
		}
	}

	log.Info().Int("count", len(migrations)).Msg("Database migrations completed")
	return nil
}

// isDuplicateColumnError 检查是否是"列已存在"错误
func isDuplicateColumnError(err error) bool {
	return err != nil && (containsString(err.Error(), "duplicate column") ||
		containsString(err.Error(), "already exists"))
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStringHelper(s, substr))
}

func containsStringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}