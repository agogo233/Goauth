package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"

	"goauth/internal/model"
	"goauth/internal/repo"
)

var ErrInvitationExpired = errors.New("invitation expired")

type InvitationService struct {
	invitationRepo *repo.InvitationRepo
	groupRepo      *repo.GroupRepo
	db             *sqlx.DB
}

func NewInvitationService(
	invitationRepo *repo.InvitationRepo,
	groupRepo *repo.GroupRepo,
	db *sqlx.DB,
) *InvitationService {
	return &InvitationService{
		invitationRepo: invitationRepo,
		groupRepo:      groupRepo,
		db:             db,
	}
}

// CreateInvitation 创建邀请
func (s *InvitationService) CreateInvitation(
	ctx context.Context,
	email *string,
	username *string,
	name *string,
	emailVerified bool,
	groupIDs []string,
	createdBy string,
	expiresInHours int,
) (*model.Invitation, error) {
	// 生成邀请挑战码
	challenge, err := generateChallenge(32)
	if err != nil {
		return nil, err
	}

	// 设置过期时间
	if expiresInHours <= 0 {
		expiresInHours = 72 // 默认 72 小时
	}
	expiresAt := model.CustomTime{Time: time.Now().Add(time.Duration(expiresInHours) * time.Hour)}

	invitation := &model.Invitation{
		Email:         email,
		Username:      username,
		Name:          name,
		Challenge:     challenge,
		EmailVerified: emailVerified,
		CreatedBy:     createdBy,
		ExpiresAt:     expiresAt,
	}

	if err := s.invitationRepo.Create(ctx, invitation, groupIDs); err != nil {
		return nil, err
	}

	return invitation, nil
}

// GetInvitationByChallenge 通过挑战码获取邀请（验证邀请链接时使用）
func (s *InvitationService) GetInvitationByChallenge(ctx context.Context, challenge string) (*model.Invitation, []string, error) {
	invitation, err := s.invitationRepo.FindByChallenge(ctx, challenge)
	if err != nil {
		return nil, nil, err
	}

	groupIDs, err := s.invitationRepo.GetInvitationGroups(ctx, invitation.ID)
	if err != nil {
		return nil, nil, err
	}

	return invitation, groupIDs, nil
}

// ValidateInvitation 验证邀请是否有效
// token 可以是邀请 ID（UUID）或 Challenge 码
func (s *InvitationService) ValidateInvitation(ctx context.Context, token string) (*model.Invitation, []string, error) {
	invitation, err := s.invitationRepo.FindByID(ctx, token)
	if err != nil {
		invitation, err = s.invitationRepo.FindByChallenge(ctx, token)
		if err != nil {
			return nil, nil, err
		}
	}

	if invitation.ExpiresAt.Before(time.Now()) {
		return nil, nil, ErrInvitationExpired
	}

	groupIDs, err := s.invitationRepo.GetInvitationGroups(ctx, invitation.ID)
	if err != nil {
		return nil, nil, err
	}

	return invitation, groupIDs, nil
}

// ListInvitations 列出邀请
func (s *InvitationService) ListInvitations(ctx context.Context) ([]*model.Invitation, error) {
	return s.invitationRepo.List(ctx)
}

// DeleteInvitation 删除邀请
func (s *InvitationService) DeleteInvitation(ctx context.Context, id string) error {
	return s.invitationRepo.Delete(ctx, id)
}

// CleanupExpired 清理过期邀请
func (s *InvitationService) CleanupExpired(ctx context.Context) (int64, error) {
	return s.invitationRepo.CleanupExpired(ctx)
}

// generateChallenge 生成随机挑战码
func generateChallenge(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
