package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CORS 跨域中间件
// 精确匹配的 origin 回显并允许携带凭据；
// 通配符 "*" 放行时不携带凭据（符合 Fetch 规范，禁止 "*"+credentials 组合）。
func CORS(allowOrigins []string) gin.HandlerFunc {
	wildcard := false
	originSet := make(map[string]bool, len(allowOrigins))
	for _, o := range allowOrigins {
		if o == "*" {
			wildcard = true
		} else if o != "" {
			originSet[o] = true
		}
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" {
			allowed := wildcard || originSet[origin]
			if allowed {
				if originSet[origin] {
					c.Header("Access-Control-Allow-Origin", origin)
					c.Header("Access-Control-Allow-Credentials", "true")
				} else {
					c.Header("Access-Control-Allow-Origin", "*")
				}
				c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Requested-With")
				c.Header("Access-Control-Max-Age", "86400")
			}
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
