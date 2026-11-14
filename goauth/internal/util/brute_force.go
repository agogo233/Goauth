package util

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// BruteForceProtector 暴力破解防护
type BruteForceProtector struct {
	db              *sqlx.DB
	maxAttempts     int
	blockMinutes    int
	totpMaxAttempts int // TOTP 独立封锁阈值（默认 5，低于登录的 10）
}

// NewBruteForceProtector 创建暴力破解防护器
// totpMaxAttempts <= 0 时回退为 maxAttempts
func NewBruteForceProtector(db *sqlx.DB, maxAttempts, blockMinutes, totpMaxAttempts int) *BruteForceProtector {
	if totpMaxAttempts <= 0 {
		totpMaxAttempts = maxAttempts
	}
	return &BruteForceProtector{
		db:              db,
		maxAttempts:     maxAttempts,
		blockMinutes:    blockMinutes,
		totpMaxAttempts: totpMaxAttempts,
	}
}

// RecordAttempt 记录登录尝试
func (p *BruteForceProtector) RecordAttempt(ctx context.Context, username, ip string, success bool) error {
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO login_attempts (id, username, ip, success, createdAt)
		VALUES (?, ?, ?, ?, ?)
	`, uuid.NewString(), username, ip, success, time.Now())
	return err
}

// IsBlocked 检查是否被封锁
// 只封锁 IP，不封锁用户名，防止攻击者通过故意失败来封锁其他用户
func (p *BruteForceProtector) IsBlocked(ctx context.Context, username, ip string) (bool, error) {
	blockTime := time.Now().Add(-time.Duration(p.blockMinutes) * time.Minute)

	// 只检查 IP 封锁
	var ipAttempts int
	err := p.db.GetContext(ctx, &ipAttempts, `
		SELECT COUNT(*) FROM login_attempts
		WHERE ip = ? AND success = 0 AND createdAt > ?
	`, ip, blockTime)
	if err != nil {
		return false, err
	}

	return ipAttempts >= p.maxAttempts, nil
}

// ClearAttempts 清除登录尝试记录
func (p *BruteForceProtector) ClearAttempts(ctx context.Context, username string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE username = ?`, username)
	return err
}

// CleanupOldAttempts 清理旧的登录尝试记录
func (p *BruteForceProtector) CleanupOldAttempts(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	_, err := p.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE createdAt < ?`, cutoff)
	return err
}

// GetRemainingAttempts 获取剩余尝试次数（基于 IP）
func (p *BruteForceProtector) GetRemainingAttempts(ctx context.Context, ip string) (int, error) {
	blockTime := time.Now().Add(-time.Duration(p.blockMinutes) * time.Minute)

	var count int
	err := p.db.GetContext(ctx, &count, `
		SELECT COUNT(*) FROM login_attempts
		WHERE ip = ? AND success = 0 AND createdAt > ?
	`, ip, blockTime)
	if err != nil {
		if err == sql.ErrNoRows {
			return p.maxAttempts, nil
		}
		return 0, err
	}

	remaining := p.maxAttempts - count
	if remaining < 0 {
		remaining = 0
	}
	return remaining, nil
}

// RecordTotpAttempt 记录 TOTP 验证尝试
// 使用 "totp:{userID}" 作为 username 存储，与普通登录尝试区分
func (p *BruteForceProtector) RecordTotpAttempt(ctx context.Context, userID, ip string, success bool) error {
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO login_attempts (id, username, ip, success, createdAt)
		VALUES (?, ?, ?, ?, ?)
	`, uuid.NewString(), "totp:"+userID, ip, success, time.Now())
	return err
}

// GetTotpAttempts 获取 TOTP 失败尝试次数
func (p *BruteForceProtector) GetTotpAttempts(ctx context.Context, userID, ip string) (int, error) {
	blockTime := time.Now().Add(-time.Duration(p.blockMinutes) * time.Minute)

	var count int
	err := p.db.GetContext(ctx, &count, `
		SELECT COUNT(*) FROM login_attempts
		WHERE username = ? AND ip = ? AND success = 0 AND createdAt > ?
	`, "totp:"+userID, ip, blockTime)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	return count, nil
}

// IsTotpBlocked 检查 TOTP 是否被封锁（使用独立阈值 totpMaxAttempts）
func (p *BruteForceProtector) IsTotpBlocked(ctx context.Context, userID, ip string) (bool, error) {
	count, err := p.GetTotpAttempts(ctx, userID, ip)
	if err != nil {
		return false, err
	}
	return count >= p.totpMaxAttempts, nil
}

// ClearTotpAttempts 清除 TOTP 尝试记录
func (p *BruteForceProtector) ClearTotpAttempts(ctx context.Context, userID string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE username = ?`, "totp:"+userID)
	return err
}
