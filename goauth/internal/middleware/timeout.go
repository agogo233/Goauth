package middleware

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
)

// RequestTimeoutKey 用于在 gin.Context 中存储请求级超时 context
const RequestTimeoutKey = "requestTimeout"

// RequestTimeout 为每个请求创建带超时的 context，
// 防止慢查询/下游阻塞长期占用连接。
// handler 内部应使用 c.Request.Context() 获取该 context。
func RequestTimeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if timeout <= 0 {
			c.Next()
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		// 替换请求 context，后续 handler 通过 c.Request.Context() 使用
		c.Request = c.Request.WithContext(ctx)
		c.Set(RequestTimeoutKey, cancel)

		c.Next()
	}
}
