package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"goauth/internal/config"
	"goauth/internal/model"
	"goauth/internal/repo"
	"goauth/internal/util"
)

var (
	ErrInvalidCredentials  = errors.New("用户名或密码错误")
	ErrUserNotFound        = errors.New("用户不存在")
	ErrUserNotApproved     = errors.New("用户未批准")
	ErrUserDisabled        = errors.New("用户已被禁用")
	ErrUserUnverified      = errors.New("邮箱未验证")
	ErrAccountLocked       = errors.New("账户已锁定，请稍后重试")
	ErrTotpRequired        = errors.New("需要 TOTP 验证")
	ErrInvalidTotpCode     = errors.New("无效的 TOTP 验证码")
	ErrUsernameEmpty       = errors.New("用户名不能为空")
	ErrInviteInvalid       = errors.New("邀请链接无效或已过期")
)

// AuthService 认证服务
type AuthService struct {
	userRepo          *repo.UserRepo
	sessionRepo       *repo.SessionRepo
	groupRepo         *repo.GroupRepo
	totpService       *TotpService
	invitationService *InvitationService
	protector         *util.BruteForceProtector
	cfg               *config.Config
}

// NewAuthService 创建认证服务
func NewAuthService(
	userRepo *repo.UserRepo,
	sessionRepo *repo.SessionRepo,
	groupRepo *repo.GroupRepo,
	totpService *TotpService,
	invitationService *InvitationService,
	protector *util.BruteForceProtector,
	cfg *config.Config,
) *AuthService {
	return &AuthService{
		userRepo:          userRepo,
		sessionRepo:       sessionRepo,
		groupRepo:         groupRepo,
		totpService:       totpService,
		invitationService: invitationService,
		protector:         protector,
		cfg:               cfg,
	}
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	RememberMe bool   `json:"rememberMe"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	Token           string              `json:"token"`
	User            *model.UserResponse `json:"user"`
	ExpiresAt       time.Time           `json:"expiresAt"`
	RequireTotp     bool                `json:"requireTotp"`
	RequireMfaSetup bool                `json:"requireMfaSetup"` // 需要 MFA 但未设置 TOTP
}

// Login 登录
func (s *AuthService) Login(ctx context.Context, req *LoginRequest, ip string) (*LoginResponse, error) {
	log.Info().Str("username", req.Username).Msg("Login attempt")

	// 检查是否被封锁
	blocked, err := s.protector.IsBlocked(ctx, req.Username, ip)
	if err != nil {
		log.Error().Err(err).Msg("Failed to check block status")
	}
	if blocked {
		log.Warn().Str("username", req.Username).Msg("Account blocked")
		return nil, ErrAccountLocked
	}

	// 查找用户
	user, err := s.userRepo.FindByInput(ctx, req.Username)
	if err != nil {
		log.Warn().Err(err).Str("username", req.Username).Msg("User not found")
		_ = s.protector.RecordAttempt(ctx, req.Username, ip, false)
		return nil, ErrInvalidCredentials
	}

	log.Info().Str("userID", user.ID).Msg("User found")

	// 验证密码
	if user.PasswordHash == nil || *user.PasswordHash == "" {
		log.Warn().Str("userID", user.ID).Msg("User has no password")
		_ = s.protector.RecordAttempt(ctx, req.Username, ip, false)
		return nil, ErrInvalidCredentials
	}

	valid, err := util.VerifyPassword(req.Password, *user.PasswordHash)
	if err != nil || !valid {
		log.Warn().Err(err).Str("userID", user.ID).Bool("valid", valid).Msg("Password verification failed")
		_ = s.protector.RecordAttempt(ctx, req.Username, ip, false)
		return nil, ErrInvalidCredentials
	}

	log.Info().Str("userID", user.ID).Msg("Password verified")

	// 检查用户状态
	if user.Disabled {
		return nil, ErrUserDisabled
	}
	if !user.Approved {
		return nil, ErrUserNotApproved
	}
	if !user.EmailVerified {
		return nil, ErrUserUnverified
	}

	// 检查是否需要 TOTP
	hasTotp, err := s.totpService.IsEnabled(ctx, user.ID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to check TOTP status")
	}

	if hasTotp {
		// 创建临时会话，等待 TOTP 验证
		token := generateToken()
		expiresAt := time.Now().Add(10 * time.Minute) // 临时会话 10 分钟有效

		session := &model.Session{
			UserID:     user.ID,
			Token:      token,
			AMR:        "pwd-totp-pending", // 标记为待 TOTP 验证
			RememberMe: req.RememberMe,
			ExpiresAt:  model.CustomTime{Time: expiresAt},
		}

		if err := s.sessionRepo.Create(ctx, session); err != nil {
			return nil, err
		}

		return &LoginResponse{
			Token:       token,
			User:        nil, // 不返回用户信息，等 TOTP 验证后返回
			ExpiresAt:   expiresAt,
			RequireTotp: true,
		}, nil
	}

	// 检查是否被要求 MFA（用户级别或分组级别）
	mfaRequired := user.MFARequired
	if !mfaRequired {
		// 使用批量查询替代 N+1
		groups, err := s.groupRepo.FindByUserID(ctx, user.ID)
		if err == nil {
			for _, g := range groups {
				if g.MFARequired {
					mfaRequired = true
					break
				}
			}
		}
	}

	// 如果要求 MFA 但用户没有启用 TOTP，需要引导设置
	if mfaRequired && !hasTotp {
		// 清除登录尝试记录
		_ = s.protector.RecordAttempt(ctx, req.Username, ip, true)

		// 创建临时会话，用于 TOTP 设置
		token := generateToken()
		expiresAt := time.Now().Add(30 * time.Minute) // 临时会话 30 分钟有效

		session := &model.Session{
			UserID:     user.ID,
			Token:      token,
			AMR:        "pwd-mfa-setup-required", // 标记为需要设置 MFA
			RememberMe: req.RememberMe,
			ExpiresAt:  model.CustomTime{Time: expiresAt},
		}

		if err := s.sessionRepo.Create(ctx, session); err != nil {
			return nil, err
		}

		// 返回用户信息，前端引导用户设置 TOTP
		groups, _ := s.groupRepo.GetUserGroups(ctx, user.ID)
		userResp := user.ToResponse()
		userResp.Groups = groups

		return &LoginResponse{
			Token:           token,
			User:            userResp,
			ExpiresAt:       expiresAt,
			RequireMfaSetup: true,
		}, nil
	}

	// 清除登录尝试记录
	_ = s.protector.RecordAttempt(ctx, req.Username, ip, true)

	// 生成 token
	token := generateToken()

	// 计算过期时间
	var expiresAt time.Time
	if req.RememberMe {
		expiresAt = time.Now().Add(s.cfg.Session.TTLRemember)
	} else {
		expiresAt = time.Now().Add(s.cfg.Session.TTL)
	}

	// 创建 session
	session := &model.Session{
		UserID:     user.ID,
		Token:      token,
		AMR:        "pwd",
		RememberMe: req.RememberMe,
		ExpiresAt:  model.CustomTime{Time: expiresAt},
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	// 获取用户分组
	groups, _ := s.groupRepo.GetUserGroups(ctx, user.ID)

	// 构建响应
	userResp := user.ToResponse()
	userResp.Groups = groups

	return &LoginResponse{
		Token:      token,
		User:       userResp,
		ExpiresAt:  expiresAt,
		RequireTotp: false,
	}, nil
}

// TotpVerifyRequest TOTP 验证请求
type TotpVerifyRequest struct {
	Token string `json:"token"`
	Code  string `json:"code"`
}

// TotpVerify 验证 TOTP 完成登录
func (s *AuthService) TotpVerify(ctx context.Context, req *TotpVerifyRequest, ip string) (*LoginResponse, error) {
	// 查找临时会话
	session, err := s.sessionRepo.FindByToken(ctx, req.Token)
	if err != nil {
		return nil, errors.New("会话无效")
	}

	// 检查是否是待验证的会话
	if session.AMR != "pwd-totp-pending" {
		return nil, errors.New("会话状态无效")
	}

	// 检查过期
	if time.Now().After(session.ExpiresAt.Time) {
		_ = s.sessionRepo.Delete(ctx, session.ID)
		return nil, errors.New("会话已过期")
	}

	// 检查 TOTP 是否被封锁（使用数据库存储，防止通过删除 cookie 绕过）
	blocked, err := s.protector.IsTotpBlocked(ctx, session.UserID, ip)
	if err != nil {
		log.Error().Err(err).Msg("Failed to check TOTP block status")
	}
	if blocked {
		_ = s.sessionRepo.Delete(ctx, session.ID)
		log.Warn().Str("userID", session.UserID).Msg("TOTP blocked due to too many attempts")
		return nil, errors.New("验证码尝试次数过多，请重新登录")
	}

	// 获取当前失败次数用于显示剩余次数
	currentAttempts, _ := s.protector.GetTotpAttempts(ctx, session.UserID, ip)

	// 验证 TOTP
	valid, err := s.totpService.Verify(ctx, session.UserID, req.Code)
	if err != nil || !valid {
		log.Warn().Err(err).Str("userID", session.UserID).Bool("valid", valid).Msg("TOTP verification failed")

		// 记录失败到数据库
		_ = s.protector.RecordTotpAttempt(ctx, session.UserID, ip, false)

		// 计算剩余次数
		remaining := s.cfg.Security.TotpMaxAttempts - currentAttempts - 1
		if remaining <= 0 {
			_ = s.sessionRepo.Delete(ctx, session.ID)
			return nil, errors.New("验证码尝试次数过多，请重新登录")
		}

		return nil, fmt.Errorf("%w (剩余 %d 次尝试)", ErrInvalidTotpCode, remaining)
	}

	// 验证成功，清除 TOTP 尝试记录
	_ = s.protector.RecordTotpAttempt(ctx, session.UserID, ip, true)

	// 获取用户
	user, err := s.userRepo.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// 删除临时会话
	_ = s.sessionRepo.Delete(ctx, session.ID)

	// 创建正式会话
	token := generateToken()
	var expiresAt time.Time
	if session.RememberMe {
		expiresAt = time.Now().Add(s.cfg.Session.TTLRemember)
	} else {
		expiresAt = time.Now().Add(s.cfg.Session.TTL)
	}

	newSession := &model.Session{
		UserID:     user.ID,
		Token:      token,
		AMR:        "pwd,totp", // 标记为密码 + TOTP 认证
		RememberMe: session.RememberMe,
		ExpiresAt:  model.CustomTime{Time: expiresAt},
	}

	if err := s.sessionRepo.Create(ctx, newSession); err != nil {
		return nil, err
	}

	// 获取用户分组
	groups, _ := s.groupRepo.GetUserGroups(ctx, user.ID)

	// 构建响应
	userResp := user.ToResponse()
	userResp.Groups = groups
	userResp.HasTotp = true // TOTP 验证通过，说明已启用

	return &LoginResponse{
		Token:       token,
		User:        userResp,
		ExpiresAt:   expiresAt,
		RequireTotp: false,
	}, nil
}

// Logout 登出
func (s *AuthService) Logout(ctx context.Context, token string) error {
	return s.sessionRepo.DeleteByToken(ctx, token)
}

// ValidateSession 验证 Session（仅返回用户，兼容旧调用）
func (s *AuthService) ValidateSession(ctx context.Context, token string) (*model.User, error) {
	user, _, err := s.ValidateSessionWithAMR(ctx, token)
	return user, err
}

// ValidateSessionWithAMR 验证 Session 并返回 session 信息
func (s *AuthService) ValidateSessionWithAMR(ctx context.Context, token string) (*model.User, *model.Session, error) {
	session, err := s.sessionRepo.FindByToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}

	if time.Now().After(session.ExpiresAt.Time) {
		_ = s.sessionRepo.Delete(ctx, session.ID)
		return nil, nil, errors.New("session expired")
	}

	user, err := s.userRepo.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, nil, err
	}

	if user.Disabled {
		_ = s.sessionRepo.Delete(ctx, session.ID)
		return nil, nil, ErrUserDisabled
	}

	return user, session, nil
}

// RefreshSession 刷新 Session 过期时间（滑动过期）
// 当 session 剩余时间少于 TTL 的一半时，自动续期
// 通过 LastRefreshedAt 防抖，避免同一周期内重复写库
// 返回新的过期时间，如果不需要续期则返回原过期时间
func (s *AuthService) RefreshSession(ctx context.Context, session *model.Session) (time.Time, error) {
	now := time.Now()

	// 确定 session 的完整 TTL
	var ttl time.Duration
	if session.RememberMe {
		ttl = s.cfg.Session.TTLRemember
	} else {
		ttl = s.cfg.Session.TTL
	}

	// 防抖：距离上次续期不足 TTL/4 则跳过，减少写操作
	if !session.LastRefreshedAt.Time.IsZero() {
		sinceLastRefresh := now.Sub(session.LastRefreshedAt.Time)
		if sinceLastRefresh < ttl/4 {
			return session.ExpiresAt.Time, nil
		}
	}

	remaining := session.ExpiresAt.Time.Sub(now)

	// 只有当剩余时间少于 TTL 的一半时才续期
	if remaining > ttl/2 {
		return session.ExpiresAt.Time, nil
	}

	// 续期
	newExpiresAt := now.Add(ttl)
	err := s.sessionRepo.UpdateExpiresAt(ctx, session.ID, model.CustomTime{Time: newExpiresAt})
	if err != nil {
		log.Error().Err(err).Str("sessionID", session.ID).Msg("Failed to refresh session")
		return session.ExpiresAt.Time, err
	}

	log.Debug().Str("sessionID", session.ID).Time("newExpiresAt", newExpiresAt).Msg("Session refreshed")
	return newExpiresAt, nil
}

// RegisterRequest 注册请求
type RegisterRequest struct {
	Username    string  `json:"username"`
	Password    string  `json:"password"`
	Email       *string `json:"email"`
	Name        *string `json:"name"`
	InviteToken *string `json:"inviteToken"`
}

// RegisterResponse 注册响应
type RegisterResponse struct {
	User     *model.UserResponse `json:"user"`
	Message  string              `json:"message"`
}

// Register 注册
func (s *AuthService) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	if req.Username == "" {
		return nil, ErrUsernameEmpty
	}

	if req.Email != nil && *req.Email != "" && !util.IsValidEmail(*req.Email) {
		return nil, util.ErrEmailInvalid
	}

	if err := util.CheckPasswordStrength(req.Password, s.cfg.Security.PasswordMin, s.cfg.Security.PasswordMinScore); err != nil {
		return nil, err
	}

	passwordHash, err := util.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	// 解析邀请（如果提供了邀请 token）
	var (
		inv             *model.Invitation
		inviteGroupIDs  []string
		hasValidInvite  bool
	)
	if req.InviteToken != nil && *req.InviteToken != "" {
		var groupIDs []string
		var err error
		inv, groupIDs, err = s.invitationService.ValidateInvitation(ctx, *req.InviteToken)
		if err != nil {
			return nil, ErrInviteInvalid
		}
		inviteGroupIDs = groupIDs
		hasValidInvite = true
	}

	// 检查是否是第一个用户（自动成为管理员）
	count, err := s.userRepo.Count(ctx)
	if err != nil {
		return nil, err
	}
	isFirstUser := count == 0

	approved := isFirstUser || s.cfg.Security.AutoApproveUsers || hasValidInvite

	emailVerified := isFirstUser || s.cfg.Security.AutoApproveUsers
	if hasValidInvite && inv.EmailVerified {
		emailVerified = true
	}

	user := &model.User{
		Username:      req.Username,
		PasswordHash:  &passwordHash,
		Email:         req.Email,
		Name:          req.Name,
		IsAdmin:       isFirstUser,
		EmailVerified: emailVerified,
		Approved:      approved,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// 如果有邀请关联分组，自动将用户加入分组
	for _, groupID := range inviteGroupIDs {
		_ = s.groupRepo.AddUserToGroup(ctx, user.ID, groupID)
	}

	message := "注册成功"
	if !approved {
		message = "注册成功，请等待管理员审批"
	}

	return &RegisterResponse{
		User:    user.ToResponse(),
		Message: message,
	}, nil
}

// generateToken 生成随机 token
func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
