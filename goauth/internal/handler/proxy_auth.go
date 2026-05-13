package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"goauth/internal/repo"
	"goauth/internal/service"
)

// sanitizeHeader 清理 header 值中的换行符，防止 HTTP Header 注入攻击
// 攻击者可能通过在用户名中注入 \r\n 来添加额外的 HTTP header
func sanitizeHeader(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1 // 删除字符
		}
		return r
	}, s)
}

// ProxyAuthHandler ProxyAuth Handler
type ProxyAuthHandler struct {
	authService   *service.AuthService
	proxyAuthRepo *repo.ProxyAuthRepo
	groupRepo     *repo.GroupRepo
	sessionRepo   *repo.SessionRepo
}

// NewProxyAuthHandler 创建 ProxyAuth Handler
func NewProxyAuthHandler(
	authService *service.AuthService,
	proxyAuthRepo *repo.ProxyAuthRepo,
	groupRepo *repo.GroupRepo,
	sessionRepo *repo.SessionRepo,
) *ProxyAuthHandler {
	return &ProxyAuthHandler{
		authService:   authService,
		proxyAuthRepo: proxyAuthRepo,
		groupRepo:     groupRepo,
		sessionRepo:   sessionRepo,
	}
}

// ForwardAuth Traefik ForwardAuth 端点
// 验证用户是否已登录，以及是否有权限访问指定域名
func (h *ProxyAuthHandler) ForwardAuth(c *gin.Context) {
	// 从请求中获取目标域名
	domain := c.Query("domain")
	if domain == "" {
		// 从 Host header 提取域名
		host := c.Request.Host
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}
		domain = host
	}

	// 获取 session token
	token, err := c.Cookie("session")
	if err != nil || token == "" {
		// 尝试从 Authorization header 获取
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if token == "" {
		c.Status(http.StatusUnauthorized)
		return
	}

	// 验证 session
	user, session, err := h.authService.ValidateSessionWithAMR(c.Request.Context(), token)
	if err != nil || user == nil {
		c.Status(http.StatusUnauthorized)
		return
	}

	// 检查用户是否被禁用
	if user.Disabled {
		c.Status(http.StatusUnauthorized)
		return
	}

	// 查找 ProxyAuth 配置
	proxyAuth, err := h.proxyAuthRepo.FindByDomain(c.Request.Context(), domain)
	if err != nil {
		// 没有配置则允许所有已登录用户
		c.Header("X-User-Id", sanitizeHeader(user.ID))
		c.Header("X-User-Name", sanitizeHeader(user.Username))
		if user.Email != nil {
			c.Header("X-User-Email", sanitizeHeader(*user.Email))
		}
		c.Status(http.StatusOK)
		return
	}

	// 检查最大会话时长
	if proxyAuth.MaxSessionLength != nil && *proxyAuth.MaxSessionLength > 0 && h.sessionRepo != nil {
		session, err := h.sessionRepo.FindByToken(c.Request.Context(), token)
		if err == nil {
			maxDuration := time.Duration(*proxyAuth.MaxSessionLength) * time.Minute
			if time.Since(session.CreatedAt.Time) > maxDuration {
				c.Status(http.StatusUnauthorized)
				return
			}
		}
	}

	// 检查 MFA 要求
	if proxyAuth.MFARequired {
		if session == nil || !strings.Contains(session.AMR, "totp") {
			c.Status(http.StatusForbidden)
			return
		}
	}

	// 检查分组限制
	groupIDs, err := h.proxyAuthRepo.GetProxyAuthGroups(c.Request.Context(), proxyAuth.ID)
	if err == nil && len(groupIDs) > 0 {
		// 有分组限制，检查用户是否在允许的分组中
		userGroups, err := h.groupRepo.GetUserGroups(c.Request.Context(), user.ID)
		if err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}

		allowed := false
		for _, ug := range userGroups {
			for _, ag := range groupIDs {
				if ug.ID == ag {
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}

		if !allowed {
			c.Status(http.StatusForbidden)
			return
		}
	}

	// 返回用户信息给反向代理
	c.Header("X-User-Id", sanitizeHeader(user.ID))
	c.Header("X-User-Name", sanitizeHeader(user.Username))
	if user.Email != nil {
		c.Header("X-User-Email", sanitizeHeader(*user.Email))
	}
	c.Status(http.StatusOK)
}

// AuthRequest Nginx Auth Request 端点
// 与 ForwardAuth 类似，但遵循 Nginx auth_request 模块的约定
func (h *ProxyAuthHandler) AuthRequest(c *gin.Context) {
	// Nginx auth_request 通常通过 original_uri 传递原始请求信息
	// 这里我们主要检查 session

	// 从 cookie 获取 session token
	token, err := c.Cookie("session")
	if err != nil || token == "" {
		// 尝试从 Authorization header 获取
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if token == "" {
		c.Status(http.StatusUnauthorized)
		return
	}

	// 验证 session
	user, err := h.authService.ValidateSession(c.Request.Context(), token)
	if err != nil || user == nil {
		c.Status(http.StatusUnauthorized)
		return
	}

	// 检查用户是否被禁用
	if user.Disabled {
		c.Status(http.StatusUnauthorized)
		return
	}

	// 设置响应头供 Nginx 使用
	c.Header("X-User-Id", sanitizeHeader(user.ID))
	c.Header("X-User-Name", sanitizeHeader(user.Username))
	if user.Email != nil {
		c.Header("X-User-Email", sanitizeHeader(*user.Email))
	}
	c.Status(http.StatusOK)
}
