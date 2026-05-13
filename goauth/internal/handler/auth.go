package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"goauth/internal/config"
	"goauth/internal/middleware"
	"goauth/internal/repo"
	"goauth/internal/service"
	"goauth/internal/util"
)

// AuthHandler 认证 Handler
type AuthHandler struct {
	authService  *service.AuthService
	userService  *service.UserService
	auditService *service.AuditService
	cfg          *config.Config
}

// NewAuthHandler 创建认证 Handler
func NewAuthHandler(authService *service.AuthService, userService *service.UserService, auditService *service.AuditService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		userService:  userService,
		auditService: auditService,
		cfg:          cfg,
	}
}

// setSessionCookie 设置 session cookie，根据配置自动处理 Secure 和 SameSite
func (h *AuthHandler) setSessionCookie(c *gin.Context, token string, maxAge int) {
	secure := h.cfg.IsCookieSecure()
	sameSite := h.cfg.GetCookieSameSite()
	domain := h.cfg.Server.CookieDomain

	// 设置 SameSite 属性
	var sameSiteValue http.SameSite
	switch sameSite {
	case "strict":
		sameSiteValue = http.SameSiteStrictMode
	case "none":
		sameSiteValue = http.SameSiteNoneMode
	default: // lax
		sameSiteValue = http.SameSiteLaxMode
	}

	c.SetSameSite(sameSiteValue)
	c.SetCookie("session", token, maxAge, "/", domain, secure, true)
}

// setCSRFToken 设置 CSRF token cookie
func (h *AuthHandler) setCSRFToken(c *gin.Context) {
	csrfToken, err := middleware.GenerateCSRFToken()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate CSRF token")
		return
	}

	secure := h.cfg.IsCookieSecure()
	sameSite := h.cfg.GetCookieSameSite()
	domain := h.cfg.Server.CookieDomain

	var sameSiteValue http.SameSite
	switch sameSite {
	case "strict":
		sameSiteValue = http.SameSiteStrictMode
	case "none":
		sameSiteValue = http.SameSiteNoneMode
	default:
		sameSiteValue = http.SameSiteLaxMode
	}

	middleware.SetCSRFToken(c, csrfToken, secure, sameSiteValue, domain)
}

// Login 登录
func (h *AuthHandler) Login(c *gin.Context) {
	var req service.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	ip := c.ClientIP()
	resp, err := h.authService.Login(c.Request.Context(), &req, ip)
	if err != nil {
		switch err {
		case service.ErrInvalidCredentials:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		case service.ErrAccountLocked:
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "账户已锁定，请稍后重试"})
		case service.ErrUserDisabled:
			c.JSON(http.StatusForbidden, gin.H{"error": "用户已被禁用"})
		case service.ErrUserNotApproved:
			c.JSON(http.StatusForbidden, gin.H{"error": "用户未批准"})
		case service.ErrUserUnverified:
			c.JSON(http.StatusForbidden, gin.H{"error": "邮箱未验证"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "登录失败"})
		}
		return
	}

	// 如果需要 TOTP 验证，返回临时 token
	if resp.RequireTotp {
		// 设置临时 cookie（10 分钟有效）
		maxAge := int(time.Until(resp.ExpiresAt).Seconds())
		h.setSessionCookie(c, resp.Token, maxAge)
		// 设置 CSRF token（TOTP 验证需要）
		h.setCSRFToken(c)
		c.JSON(http.StatusOK, gin.H{
			"requireTotp": true,
			"message":     "请输入 TOTP 验证码",
		})
		return
	}

	if resp.User != nil {
		_ = h.auditService.LogLogin(c.Request.Context(), resp.User.ID, ip, true)
	}

	// 设置 cookie
	maxAge := int(time.Until(resp.ExpiresAt).Seconds())
	h.setSessionCookie(c, resp.Token, maxAge)

	// 设置 CSRF token
	h.setCSRFToken(c)

	c.JSON(http.StatusOK, resp)
}

// isValidTotpCode 验证 TOTP 验证码格式（必须是 6 位数字）
func isValidTotpCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// TotpLogin TOTP 验证登录
func (h *AuthHandler) TotpLogin(c *gin.Context) {
	// 从 cookie 获取临时 token
	token, err := c.Cookie("session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "会话无效"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	// 验证验证码格式
	if !isValidTotpCode(req.Code) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "验证码必须是 6 位数字"})
		return
	}

	ip := c.ClientIP()
	resp, err := h.authService.TotpVerify(c.Request.Context(), &service.TotpVerifyRequest{
		Token: token,
		Code:  req.Code,
	}, ip)
	if err != nil {
		if errors.Is(err, service.ErrInvalidTotpCode) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		}
		return
	}

	// 记录审计日志
	_ = h.auditService.LogLogin(c.Request.Context(), resp.User.ID, ip, true)

	// 设置正式 cookie
	maxAge := int(time.Until(resp.ExpiresAt).Seconds())
	h.setSessionCookie(c, resp.Token, maxAge)

	// 设置 CSRF token
	h.setCSRFToken(c)

	c.JSON(http.StatusOK, resp)
}

// Logout 登出
func (h *AuthHandler) Logout(c *gin.Context) {
	token, err := c.Cookie("session")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "已登出"})
		return
	}

	_ = h.authService.Logout(c.Request.Context(), token)
	h.setSessionCookie(c, "", -1)

	// 清除 CSRF token
	secure := h.cfg.IsCookieSecure()
	domain := h.cfg.Server.CookieDomain
	c.SetCookie(middleware.GetCSRFCookieName(), "", -1, "/", domain, secure, false)

	c.JSON(http.StatusOK, gin.H{"message": "已登出"})
}

// Register 注册
func (h *AuthHandler) Register(c *gin.Context) {
	var req service.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	resp, err := h.authService.Register(c.Request.Context(), &req)
	if err != nil {
		switch err {
		case util.ErrPasswordTooShort:
			c.JSON(http.StatusBadRequest, gin.H{"error": "密码太短"})
		case util.ErrPasswordTooWeak:
			c.JSON(http.StatusBadRequest, gin.H{"error": "密码强度不足"})
		case util.ErrEmailInvalid:
			c.JSON(http.StatusBadRequest, gin.H{"error": "邮箱格式无效"})
		case service.ErrUsernameEmpty:
			c.JSON(http.StatusBadRequest, gin.H{"error": "用户名不能为空"})
		case service.ErrInviteInvalid:
			c.JSON(http.StatusBadRequest, gin.H{"error": "邀请链接无效或已过期"})
		case repo.ErrUserExists:
			c.JSON(http.StatusConflict, gin.H{"error": "用户名已存在"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "注册失败"})
		}
		return
	}

	// 记录审计日志
	_ = h.auditService.LogRegister(c.Request.Context(), resp.User.ID, c.ClientIP())

	c.JSON(http.StatusCreated, resp)
}


