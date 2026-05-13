package service

import (
	"context"
	"errors"

	"github.com/jmoiron/sqlx"

	"goauth/internal/config"
	"goauth/internal/model"
	"goauth/internal/repo"
	"goauth/internal/util"
)

// UserService 用户服务
type UserService struct {
	userRepo    *repo.UserRepo
	sessionRepo *repo.SessionRepo
	groupRepo   *repo.GroupRepo
	db          *sqlx.DB
	cfg         *config.Config
}

// NewUserService 创建用户服务
func NewUserService(
	userRepo *repo.UserRepo,
	sessionRepo *repo.SessionRepo,
	groupRepo *repo.GroupRepo,
	db *sqlx.DB,
	cfg *config.Config,
) *UserService {
	return &UserService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		groupRepo:   groupRepo,
		db:          db,
		cfg:         cfg,
	}
}

// GetByID 根据ID获取用户
func (s *UserService) GetByID(ctx context.Context, id string) (*model.UserResponse, error) {
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	resp := user.ToResponse()
	groups, _ := s.groupRepo.GetUserGroups(ctx, id)
	resp.Groups = groups

	return resp, nil
}

// ListUsers 列出用户
func (s *UserService) ListUsers(ctx context.Context, limit, offset int) ([]*model.UserResponse, int, error) {
	users, err := s.userRepo.List(ctx, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	count, err := s.userRepo.Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	responses := make([]*model.UserResponse, len(users))
	for i, user := range users {
		responses[i] = user.ToResponse()
	}

	return responses, count, nil
}

// UpdateProfile 更新资料
func (s *UserService) UpdateProfile(ctx context.Context, userID string, name *string, email *string) (*model.UserResponse, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if name != nil {
		user.Name = name
	}
	if email != nil {
		user.Email = email
		user.EmailVerified = false // 更新邮箱需要重新验证
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	return user.ToResponse(), nil
}

// UpdatePassword 更新密码
func (s *UserService) UpdatePassword(ctx context.Context, userID string, oldPassword, newPassword string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	// 验证旧密码
	if user.PasswordHash != nil && *user.PasswordHash != "" {
		valid, err := util.VerifyPassword(oldPassword, *user.PasswordHash)
		if err != nil || !valid {
			return errors.New("旧密码错误")
		}
	}

	// 检查新密码强度
	if err := util.CheckPasswordStrength(newPassword, s.cfg.Security.PasswordMin, s.cfg.Security.PasswordMinScore); err != nil {
		return err
	}

	// 哈希新密码
	passwordHash, err := util.HashPassword(newPassword)
	if err != nil {
		return err
	}

	user.PasswordHash = &passwordHash
	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	_ = s.sessionRepo.DeleteByUserID(ctx, userID)
	return nil
}

// AdminResetPassword 管理员重置密码
func (s *UserService) AdminResetPassword(ctx context.Context, userID string, newPassword string) error {
	// 检查密码强度
	if err := util.CheckPasswordStrength(newPassword, s.cfg.Security.PasswordMin, s.cfg.Security.PasswordMinScore); err != nil {
		return err
	}

	// 哈希密码
	passwordHash, err := util.HashPassword(newPassword)
	if err != nil {
		return err
	}

	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	user.PasswordHash = &passwordHash
	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	// 删除所有 session，强制重新登录
	return s.sessionRepo.DeleteByUserID(ctx, userID)
}

// ApproveUser 审批用户
func (s *UserService) ApproveUser(ctx context.Context, userID string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	user.Approved = true
	// 修复：审批时不自动验证邮箱，让用户自行通过邮件链接验证
	return s.userRepo.Update(ctx, user)
}

// DisableUser 禁用用户
func (s *UserService) DisableUser(ctx context.Context, userID string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	user.Disabled = true
	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	// 删除所有 session
	return s.sessionRepo.DeleteByUserID(ctx, userID)
}

// EnableUser 启用用户
func (s *UserService) EnableUser(ctx context.Context, userID string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	user.Disabled = false
	return s.userRepo.Update(ctx, user)
}

// DeleteUser 删除用户
func (s *UserService) DeleteUser(ctx context.Context, userID string) error {
	return s.userRepo.Delete(ctx, userID)
}

// SetAdmin 设置管理员权限
func (s *UserService) SetAdmin(ctx context.Context, userID string, isAdmin bool) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	user.IsAdmin = isAdmin
	return s.userRepo.Update(ctx, user)
}

// GetUserSessions 获取用户的所有 Session
func (s *UserService) GetUserSessions(ctx context.Context, userID string) ([]*model.Session, error) {
	return s.sessionRepo.FindByUserID(ctx, userID)
}

// TerminateSession 终止指定 Session
func (s *UserService) TerminateSession(ctx context.Context, sessionID string) error {
	return s.sessionRepo.Delete(ctx, sessionID)
}
