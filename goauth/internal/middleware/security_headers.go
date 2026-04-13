package middleware

import (
	"github.com/gin-gonic/gin"
)

// SecurityHeaders 安全响应头中间件
// 添加标准安全响应头以防护常见攻击
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 防止 MIME 类型嗅探
		c.Header("X-Content-Type-Options", "nosniff")

		// 防止点击劫持
		c.Header("X-Frame-Options", "DENY")

		// 启用浏览器 XSS 过滤器
		c.Header("X-XSS-Protection", "1; mode=block")

		// 引用策略
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// 权限策略（替代 Feature-Policy）
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// Content-Security-Policy
		// 注意：由于使用 Alpine.js 内联脚本和内联样式，需要 'unsafe-inline'
		// Alpine.js 压缩版需要 'unsafe-eval' 来执行模板表达式 (x-bind, x-on 等)
		// 生产环境可考虑使用 nonce 或 hash 替代
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'")

		c.Next()
	}
}
