package repo

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"goauth/internal/model"
)

var ErrGroupNotFound = errors.New("group not found")

type GroupRepo struct {
	db *sqlx.DB
}

func NewGroupRepo(db *sqlx.DB) *GroupRepo {
	return &GroupRepo{db: db}
}

// Create 创建分组
func (r *GroupRepo) Create(ctx context.Context, group *model.Group) error {
	if group.ID == "" {
		group.ID = uuid.NewString()
	}
	now := model.Now()
	group.CreatedAt = now
	group.UpdatedAt = now

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO groups (id, name, mfaRequired, createdBy, createdAt, updatedAt)
		VALUES (?, ?, ?, ?, ?, ?)
	`, group.ID, group.Name, group.MFARequired, group.CreatedBy, group.CreatedAt, group.UpdatedAt)

	return err
}

// FindByID 根据 ID 查找分组
func (r *GroupRepo) FindByID(ctx context.Context, id string) (*model.Group, error) {
	var group model.Group
	err := r.db.GetContext(ctx, &group, `SELECT * FROM groups WHERE id = ?`, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrGroupNotFound
		}
		return nil, err
	}
	return &group, nil
}

// FindByName 根据名称查找分组
func (r *GroupRepo) FindByName(ctx context.Context, name string) (*model.Group, error) {
	var group model.Group
	err := r.db.GetContext(ctx, &group, `SELECT * FROM groups WHERE name = ?`, name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrGroupNotFound
		}
		return nil, err
	}
	return &group, nil
}

// Update 更新分组
func (r *GroupRepo) Update(ctx context.Context, group *model.Group) error {
	group.UpdatedAt = model.Now()
	_, err := r.db.ExecContext(ctx, `
		UPDATE groups SET name = ?, mfaRequired = ?, updatedAt = ? WHERE id = ?
	`, group.Name, group.MFARequired, group.UpdatedAt, group.ID)
	return err
}

// Delete 删除分组
func (r *GroupRepo) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id)
	return err
}

// List 列出分组
func (r *GroupRepo) List(ctx context.Context) ([]*model.Group, error) {
	var groups []*model.Group
	err := r.db.SelectContext(ctx, &groups, `SELECT * FROM groups ORDER BY name`)
	return groups, err
}

// AddUserToGroup 将用户添加到分组
func (r *GroupRepo) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO user_groups (userId, groupId, createdAt) VALUES (?, ?, ?)
	`, userID, groupID, time.Now())
	return err
}

// RemoveUserFromGroup 将用户从分组移除
func (r *GroupRepo) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM user_groups WHERE userId = ? AND groupId = ?`, userID, groupID)
	return err
}

// FindByUserID 获取用户所属分组（包含完整 Group 信息，用于 N+1 查询优化）
func (r *GroupRepo) FindByUserID(ctx context.Context, userID string) ([]*model.Group, error) {
	var groups []*model.Group
	err := r.db.SelectContext(ctx, &groups, `
		SELECT g.* FROM groups g
		INNER JOIN user_groups ug ON g.id = ug.groupId
		WHERE ug.userId = ?
	`, userID)
	return groups, err
}

// GetUserGroups 获取用户的分组（保持向后兼容）
func (r *GroupRepo) GetUserGroups(ctx context.Context, userID string) ([]*model.GroupRef, error) {
	var groups []*model.GroupRef
	err := r.db.SelectContext(ctx, &groups, `
		SELECT g.id, g.name FROM groups g
		INNER JOIN user_groups ug ON g.id = ug.groupId
		WHERE ug.userId = ?
	`, userID)
	return groups, err
}

// GetGroupMembers 获取分组的用户ID列表
func (r *GroupRepo) GetGroupMembers(ctx context.Context, groupID string) ([]string, error) {
	var userIDs []string
	err := r.db.SelectContext(ctx, &userIDs, `SELECT userId FROM user_groups WHERE groupId = ?`, groupID)
	return userIDs, err
}

// GroupWithMemberCount 分组带成员数量
type GroupWithMemberCount struct {
	ID          string `db:"id" json:"id"`
	Name        string `db:"name" json:"name"`
	MFARequired bool   `db:"mfaRequired" json:"mfaRequired"`
	MemberCount int    `db:"memberCount" json:"memberCount"`
	CreatedBy   string `db:"createdBy" json:"createdBy"`
}

// ListWithMemberCount 列出分组及其成员数量（单次查询，避免 N+1）
func (r *GroupRepo) ListWithMemberCount(ctx context.Context) ([]*GroupWithMemberCount, error) {
	var groups []*GroupWithMemberCount
	err := r.db.SelectContext(ctx, &groups, `
		SELECT g.id, g.name, g.mfaRequired, g.createdBy, COUNT(ug.userId) as memberCount
		FROM groups g
		LEFT JOIN user_groups ug ON g.id = ug.groupId
		GROUP BY g.id
		ORDER BY g.name
	`)
	return groups, err
}
