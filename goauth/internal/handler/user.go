package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"goauth/internal/config"
	"goauth/internal/model"
	"goauth/internal/repo"
	"goauth/internal/service"
)

// UserHandler 用户 Handler
type UserHandler struct {
	userService *service.UserService
	totpService *service.TotpService
	sessionRepo *repo.SessionRepo
	cfg         *config.Config
}

// NewUserHandler 创建用户 Handler
func NewUserHandler(userService *service.UserService, totpService *service.TotpService, sessionRepo *repo.SessionRepo, cfg *config.Config) *UserHandler {
	return &UserHandler{
		userService: userService,
		totpService: totpService,
		sessionRepo: sessionRepo,
		cfg:         cfg,
	}
}

// GetMe 获取当前用户
func (h *UserHandler) GetMe(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	userID, ok := userIDVal.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误"})
		return
	}

	user, err := h.userService.GetByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取用户信息失败"})
		return
	}

	// 检查 TOTP 状态
	hasTotp, _ := h.totpService.IsEnabled(c.Request.Context(), userID)
	user.HasTotp = hasTotp

	c.JSON(http.StatusOK, user)
}

// UpdateProfile 更新资料
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	userID, ok := userIDVal.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误"})
		return
	}

	var req struct {
		Name  *string `json:"name"`
		Email *string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	user, err := h.userService.UpdateProfile(c.Request.Context(), userID, req.Name, req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}

	c.JSON(http.StatusOK, user)
}

// UpdatePassword 更新密码
func (h *UserHandler) UpdatePassword(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	userID, ok := userIDVal.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误"})
		return
	}

	var req struct {
		OldPassword string `json:"oldPassword" binding:"required"`
		NewPassword string `json:"newPassword" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	err := h.userService.UpdatePassword(c.Request.Context(), userID, req.OldPassword, req.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "密码已更新"})
}

// SetupTotp 设置 TOTP
func (h *UserHandler) SetupTotp(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	userID, ok := userIDVal.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误"})
		return
	}
	usernameVal, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	username, ok := usernameVal.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误"})
		return
	}

	resp, err := h.totpService.Setup(c.Request.Context(), userID, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// VerifyTotp 验证并确认 TOTP 设置
func (h *UserHandler) VerifyTotp(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	userID, ok := userIDVal.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误"})
		return
	}

	var req struct {
		Code            string `json:"code" binding:"required"`
		Secret          string `json:"secret"`          // 明文密钥（用于验证）
		EncryptedSecret string `json:"encryptedSecret"` // 加密密钥（用于存储）
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	// 验证验证码（使用明文密钥）
	valid := h.totpService.VerifySetupCode(req.Secret, req.Code)
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "验证码无效"})
		return
	}

	// 验证成功，存储密钥
	err := h.totpService.ConfirmSetup(c.Request.Context(), userID, req.EncryptedSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 检查是否需要升级 session（从 pwd-mfa-setup-required 升级为 pwd）
	mfaSetupRequired, _ := c.Get("mfaSetupRequired")
	if mfaSetupRequired == true {
		// 从 cookie 或 header 获取 token
		token, err := c.Cookie("session")
		if err != nil {
			authHeader := c.GetHeader("Authorization")
			if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				token = authHeader[7:]
			}
		}
		if token != "" {
			// 查找并升级 session
			session, err := h.sessionRepo.FindByToken(c.Request.Context(), token)
			if err == nil && session != nil && session.AMR == "pwd-mfa-setup-required" {
				// 升级 session
				var expiresAt time.Time
				if session.RememberMe {
					expiresAt = time.Now().Add(h.cfg.Session.TTLRemember)
				} else {
					expiresAt = time.Now().Add(h.cfg.Session.TTL)
				}
				session.AMR = "pwd"
				session.ExpiresAt = model.CustomTime{Time: expiresAt}
				_ = h.sessionRepo.Update(c.Request.Context(), session)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"valid": true})
}

// RemoveTotp 移除 TOTP
func (h *UserHandler) RemoveTotp(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	userID, ok := userIDVal.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误"})
		return
	}

	err := h.totpService.Remove(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "TOTP 已移除"})
}

// GenerateBackupCodes 生成 TOTP 备用码
func (h *UserHandler) GenerateBackupCodes(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	userID, ok := userIDVal.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误"})
		return
	}

	codes, err := h.totpService.GenerateBackupCodes(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成备用码失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"codes": codes})
}

// VerifyBackupCode 验证 TOTP 备用码
func (h *UserHandler) VerifyBackupCode(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	userID, ok := userIDVal.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	valid, err := h.totpService.ValidateBackupCode(c.Request.Context(), userID, req.Code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "验证失败"})
		return
	}
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的备用码"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": true})
}

// GetSessions 获取所有 Session
func (h *UserHandler) GetSessions(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	userID, ok := userIDVal.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误"})
		return
	}
	currentSessionID, _ := c.Get("sessionID")

	sessions, err := h.userService.GetUserSessions(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取会话失败"})
		return
	}

	// 添加 current 标记
	type SessionResponse struct {
		ID           string `json:"id"`
		UserID       string `json:"userId"`
		AMR          string `json:"amr"`
		TotpAttempts int    `json:"totpAttempts"`
		RememberMe   bool   `json:"rememberMe"`
		Current      bool   `json:"current"`
		ExpiresAt    string `json:"expiresAt"`
		CreatedAt    string `json:"createdAt"`
	}

	response := make([]SessionResponse, len(sessions))
	for i, s := range sessions {
		response[i] = SessionResponse{
			ID:           s.ID,
			UserID:       s.UserID,
			AMR:          s.AMR,
			TotpAttempts: s.TotpAttempts,
			RememberMe:   s.RememberMe,
			Current:      s.ID == currentSessionID,
			ExpiresAt:    s.ExpiresAt.Time.Format("2006-01-02T15:04:05Z07:00"),
			CreatedAt:    s.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	c.JSON(http.StatusOK, response)
}

// TerminateSession 终止指定 Session
func (h *UserHandler) TerminateSession(c *gin.Context) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	userID, ok := userIDVal.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误"})
		return
	}
	sessionID := c.Param("id")

	// 验证会话属于当前用户
	session, err := h.sessionRepo.FindByID(c.Request.Context(), sessionID)
	if err != nil || session == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "会话不存在"})
		return
	}

	if session.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权终止此会话"})
		return
	}

	err = h.userService.TerminateSession(c.Request.Context(), sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "终止会话失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "会话已终止"})
}

// ListUsers 列出用户（管理员）
func (h *UserHandler) ListUsers(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	users, count, err := h.userService.ListUsers(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取用户列表失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"total": count,
	})
}

// GetUser 获取用户（管理员）
func (h *UserHandler) GetUser(c *gin.Context) {
	userID := c.Param("id")

	user, err := h.userService.GetByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	c.JSON(http.StatusOK, user)
}
