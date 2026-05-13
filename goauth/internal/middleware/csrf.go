package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// CSRFTokenLength CSRF token 长度
	CSRFTokenLength = 32
	// CSRFHeaderName CSRF header 名称
	CSRFHeaderName = "X-CSRF-Token"
	// CSRFCookieName CSRF cookie 名称
	CSRFCookieName = "csrf_token"
)

// CSRFConfig CSRF 中间件配置
type CSRFConfig struct {
	// TokenLookup 查找 token 的方式，默认 "header:X-CSRF-Token"
	TokenLookup string
	// CookieName CSRF cookie 名称
	CookieName string
	// CookiePath cookie 路径
	CookiePath string
	// CookieDomain cookie 域名
	CookieDomain string
	// CookieSecure 是否设置 Secure
	CookieSecure bool
	// CookieSameSite SameSite 属性
	CookieSameSite http.SameSite
	// CookieHTTPOnly 是否设置 HttpOnly（CSRF token 需要前端读取，所以设为 false）
	CookieHTTPOnly bool
	// SkipPaths 跳过 CSRF 验证的路径
	SkipPaths []string
	// ErrorFunc 错误处理函数
	ErrorFunc func(c *gin.Context)
}

// DefaultCSRFConfig 默认配置（安全加固）
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{
		TokenLookup:    "header:" + CSRFHeaderName,
		CookieName:     CSRFCookieName,
		CookiePath:     "/",
		CookieDomain:   "",
		CookieSecure:   true, // 强制 Secure，部署时要求 HTTPS
		CookieSameSite: http.SameSiteStrictMode, // 从 Lax 升级为 Strict，防止 CSRF
		CookieHTTPOnly: false, // 前端需要读取以附加到 header
		SkipPaths:      []string{},
		ErrorFunc: func(c *gin.Context) {
			c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token 无效"})
			c.Abort()
		},
	}
}

// CSRF 创建 CSRF 中间件
// 使用 Double Submit Cookie 模式：
// 1. 登录成功后设置 csrf_token cookie
// 2. 前端从 cookie 读取 token 并设置到 X-CSRF-Token header
// 3. 后端验证 header 与 cookie 是否匹配
func CSRF(config ...CSRFConfig) gin.HandlerFunc {
	cfg := DefaultCSRFConfig()
	if len(config) > 0 {
		if config[0].TokenLookup != "" {
			cfg.TokenLookup = config[0].TokenLookup
		}
		if config[0].CookieName != "" {
			cfg.CookieName = config[0].CookieName
		}
		if config[0].CookiePath != "" {
			cfg.CookiePath = config[0].CookiePath
		}
		if config[0].CookieDomain != "" {
			cfg.CookieDomain = config[0].CookieDomain
		}
		if config[0].CookieSecure {
			cfg.CookieSecure = true
		}
		if config[0].CookieSameSite != 0 {
			cfg.CookieSameSite = config[0].CookieSameSite
		}
		if config[0].ErrorFunc != nil {
			cfg.ErrorFunc = config[0].ErrorFunc
		}
		if len(config[0].SkipPaths) > 0 {
			cfg.SkipPaths = config[0].SkipPaths
		}
	}

	// 解析 token 查找方式
	parts := strings.Split(cfg.TokenLookup, ":")
	if len(parts) != 2 {
		panic("invalid token lookup format")
	}
	source := parts[0] // "header"
	name := parts[1]   // "X-CSRF-Token"

	// 构建跳过路径的快速查找 map
	skipMap := make(map[string]bool)
	for _, path := range cfg.SkipPaths {
		skipMap[path] = true
	}

	return func(c *gin.Context) {
		// 检查是否在跳过列表中
		if skipMap[c.Request.URL.Path] {
			c.Next()
			return
		}

		// 只对状态改变方法进行验证（POST, PUT, PATCH, DELETE）
		method := c.Request.Method
		if method != http.MethodPost && method != http.MethodPut &&
			method != http.MethodPatch && method != http.MethodDelete {
			c.Next()
			return
		}

		// 从 cookie 获取 CSRF token
		cookieToken, err := c.Cookie(cfg.CookieName)
		if err != nil || cookieToken == "" {
			cfg.ErrorFunc(c)
			return
		}

		// 从请求中获取 token
		var requestToken string
		switch source {
		case "header":
			requestToken = c.GetHeader(name)
		case "query":
			requestToken = c.Query(name)
		case "form":
			requestToken = c.PostForm(name)
		}

		// 验证 token
		if requestToken == "" || requestToken != cookieToken {
			cfg.ErrorFunc(c)
			return
		}

		c.Next()
	}
}

// GenerateCSRFToken 生成 CSRF token
func GenerateCSRFToken() (string, error) {
	b := make([]byte, CSRFTokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SetCSRFToken 设置 CSRF token cookie
func SetCSRFToken(c *gin.Context, token string, secure bool, sameSite http.SameSite, domain string) {
	c.SetSameSite(sameSite)
	c.SetCookie(CSRFCookieName, token, 0, "/", domain, secure, false)
}

// GetCSRFCookieName 获取 CSRF cookie 名称
func GetCSRFCookieName() string {
	return CSRFCookieName
}
