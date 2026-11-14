package repo

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"goauth/internal/model"
)

var ErrUserNotFound = errors.New("user not found")
var ErrUserExists = errors.New("user already exists")

type UserRepo struct {
	db *sqlx.DB
}

func NewUserRepo(db *sqlx.DB) *UserRepo {
	return &UserRepo{db: db}
}

// Create 创建用户
func (r *UserRepo) Create(ctx context.Context, user *model.User) error {
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	now := model.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	// 规范化邮箱：去空格 + 转小写；空邮箱统一存 NULL，避免 "" UNIQUE 冲突
	user.Email = normalizeEmail(user.Email)

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (id, email, username, name, passwordHash, isAdmin, emailVerified, approved, mfaRequired, disabled, createdAt, updatedAt)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, user.ID, user.Email, user.Username, user.Name, user.PasswordHash, user.IsAdmin, user.EmailVerified, user.Approved, user.MFARequired, user.Disabled, now, now)

	if err != nil {
		// SQLite UNIQUE 约束错误
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrUserExists
		}
		return err
	}
	return nil
}

// FindByID 根据 ID 查找用户
func (r *UserRepo) FindByID(ctx context.Context, id string) (*model.User, error) {
	var user model.User
	err := r.db.GetContext(ctx, &user, `SELECT * FROM users WHERE id = ?`, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// FindByUsername 根据用户名查找用户
func (r *UserRepo) FindByUsername(ctx context.Context, username string) (*model.User, error) {
	var user model.User
	err := r.db.GetContext(ctx, &user, `SELECT * FROM users WHERE username = ?`, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// FindByEmail 根据邮箱查找用户（邮箱小写规范化查询）
func (r *UserRepo) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User
	err := r.db.GetContext(ctx, &user, `SELECT * FROM users WHERE email = ?`, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// FindByInput 根据用户名或邮箱查找用户
// 邮箱匹配时做与小写规范化一致的查询
func (r *UserRepo) FindByInput(ctx context.Context, input string) (*model.User, error) {
	var user model.User
	lowerInput := strings.ToLower(strings.TrimSpace(input))
	err := r.db.GetContext(ctx, &user, `SELECT * FROM users WHERE username = ? OR email = ?`, input, lowerInput)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// Update 更新用户
func (r *UserRepo) Update(ctx context.Context, user *model.User) error {
	now := model.Now()
	user.UpdatedAt = now

	// 规范化邮箱：去空格 + 转小写；空邮箱统一存 NULL，避免 "" UNIQUE 冲突
	user.Email = normalizeEmail(user.Email)

	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET email = ?, username = ?, name = ?, passwordHash = ?, isAdmin = ?, emailVerified = ?, approved = ?, mfaRequired = ?, disabled = ?, updatedAt = ?
		WHERE id = ?
	`, user.Email, user.Username, user.Name, user.PasswordHash, user.IsAdmin, user.EmailVerified, user.Approved, user.MFARequired, user.Disabled, now, user.ID)
	return err
}

// normalizeEmail 规范化邮箱指针：trim + 小写；空字符串归一为 nil（NULL）
// 避免多个空邮箱命中 email UNIQUE 约束
func normalizeEmail(email *string) *string {
	if email == nil {
		return nil
	}
	trimmed := strings.ToLower(strings.TrimSpace(*email))
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

// Delete 删除用户
func (r *UserRepo) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// List 列出用户
func (r *UserRepo) List(ctx context.Context, limit, offset int) ([]*model.User, error) {
	var users []*model.User
	err := r.db.SelectContext(ctx, &users, `SELECT * FROM users ORDER BY createdAt DESC LIMIT ? OFFSET ?`, limit, offset)
	return users, err
}

// Count 统计用户数量
func (r *UserRepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.GetContext(ctx, &count, `SELECT COUNT(*) FROM users`)
	return count, err
}

// CountApproved 统计已批准用户数量
func (r *UserRepo) CountApproved(ctx context.Context) (int, error) {
	var count int
	err := r.db.GetContext(ctx, &count, `SELECT COUNT(*) FROM users WHERE approved = 1`)
	return count, err
}

// FindByIDs 根据多个 ID 批量查找用户（避免 N+1 查询）
func (r *UserRepo) FindByIDs(ctx context.Context, ids []string) ([]*model.User, error) {
	if len(ids) == 0 {
		return []*model.User{}, nil
	}

	// 构建 IN 查询
	query, args, err := sqlx.In(`SELECT * FROM users WHERE id IN (?)`, ids)
	if err != nil {
		return nil, err
	}

	// sqlx.In 返回的是带 ? 占位符的查询，需要用 r.db.Rebind 转换
	query = r.db.Rebind(query)

	var users []*model.User
	err = r.db.SelectContext(ctx, &users, query, args...)
	return users, err
}
