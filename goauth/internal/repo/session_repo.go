package repo

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"goauth/internal/model"
)

var ErrSessionNotFound = errors.New("session not found")

type SessionRepo struct {
	db *sqlx.DB
}

func NewSessionRepo(db *sqlx.DB) *SessionRepo {
	return &SessionRepo{db: db}
}

// Create 创建 Session
func (r *SessionRepo) Create(ctx context.Context, session *model.Session) error {
	if session.ID == "" {
		session.ID = uuid.NewString()
	}
	session.CreatedAt = model.Now()

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sessions (id, userId, token, amr, rememberMe, expiresAt, createdAt)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, session.ID, session.UserID, session.Token, session.AMR, session.RememberMe, session.ExpiresAt, session.CreatedAt)

	return err
}

// FindByToken 根据 Token 查找 Session
func (r *SessionRepo) FindByToken(ctx context.Context, token string) (*model.Session, error) {
	var session model.Session
	err := r.db.GetContext(ctx, &session, `SELECT * FROM sessions WHERE token = ?`, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}
	return &session, nil
}

// FindByID 根据 ID 查找 Session
func (r *SessionRepo) FindByID(ctx context.Context, id string) (*model.Session, error) {
	var session model.Session
	err := r.db.GetContext(ctx, &session, `SELECT * FROM sessions WHERE id = ?`, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}
	return &session, nil
}

// FindByUserID 根据用户 ID 查找所有 Session
func (r *SessionRepo) FindByUserID(ctx context.Context, userID string) ([]*model.Session, error) {
	var sessions []*model.Session
	err := r.db.SelectContext(ctx, &sessions, `SELECT * FROM sessions WHERE userId = ? ORDER BY createdAt DESC`, userID)
	return sessions, err
}

// Delete 删除 Session
func (r *SessionRepo) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// DeleteByToken 根据 Token 删除 Session
func (r *SessionRepo) DeleteByToken(ctx context.Context, token string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token)
	return err
}

// DeleteByUserID 删除用户的所有 Session
func (r *SessionRepo) DeleteByUserID(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE userId = ?`, userID)
	return err
}

// DeleteExpired 删除过期的 Session
func (r *SessionRepo) DeleteExpired(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE expiresAt < ?`, model.Now())
	return err
}

// UpdateExpiresAt 更新 Session 过期时间
func (r *SessionRepo) UpdateExpiresAt(ctx context.Context, id string, expiresAt model.CustomTime) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET expiresAt = ?, lastRefreshedAt = ? WHERE id = ?`, expiresAt, model.Now(), id)
	return err
}

// Update 更新 Session（AMR 和过期时间）
func (r *SessionRepo) Update(ctx context.Context, session *model.Session) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE sessions SET amr = ?, expiresAt = ? WHERE id = ?`,
		session.AMR, session.ExpiresAt, session.ID,
	)
	return err
}

// IncrementTotpAttempts 增加 TOTP 尝试次数，返回更新后的次数
func (r *SessionRepo) IncrementTotpAttempts(ctx context.Context, id string) (int, error) {
	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET totpAttempts = totpAttempts + 1 WHERE id = ?`, id)
	if err != nil {
		return 0, err
	}

	var attempts int
	err = r.db.GetContext(ctx, &attempts, `SELECT totpAttempts FROM sessions WHERE id = ?`, id)
	return attempts, err
}

// ResetTotpAttempts 重置 TOTP 尝试次数
func (r *SessionRepo) ResetTotpAttempts(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET totpAttempts = 0 WHERE id = ?`, id)
	return err
}
