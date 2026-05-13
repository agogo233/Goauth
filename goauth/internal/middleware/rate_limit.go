package middleware

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter 速率限制器
type RateLimiter struct {
	visitors    map[string]*visitor
	mu          sync.RWMutex
	rate        int           // 请求数
	window      time.Duration // 时间窗口
	maxVisitors int           // 最大访问者数（0 = 无限制）
	done        chan struct{} // 用于优雅停止 cleanup goroutine
}

type visitor struct {
	lastSeen time.Time
	count    int
}

// NewRateLimiter 创建速率限制器
// maxVisitors 为最大访问者数，0 表示使用默认值 10000
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	return NewRateLimiterWithMax(rate, window, 10000)
}

// NewRateLimiterWithMax 创建速率限制器，可指定最大访问者数
func NewRateLimiterWithMax(rate int, window time.Duration, maxVisitors int) *RateLimiter {
	if maxVisitors <= 0 {
		maxVisitors = 10000
	}
	limiter := &RateLimiter{
		visitors:    make(map[string]*visitor),
		rate:        rate,
		window:      window,
		maxVisitors: maxVisitors,
		done:        make(chan struct{}),
	}

	go limiter.cleanup()

	return limiter
}

// Stop 停止清理 goroutine，释放资源
func (rl *RateLimiter) Stop() {
	close(rl.done)
}

// Allow 检查是否允许请求
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists || time.Since(v.lastSeen) > rl.window {
		// 达到最大访问者数时，拒绝新的访问者
		if !exists && len(rl.visitors) >= rl.maxVisitors {
			return false
		}
		rl.visitors[ip] = &visitor{
			lastSeen: time.Now(),
			count:    1,
		}
		return true
	}

	v.count++
	v.lastSeen = time.Now()
	return v.count <= rl.rate
}

// cleanup 清理过期记录
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.done:
			return // 收到停止信号，退出 goroutine
		case <-ticker.C:
			rl.mu.Lock()
			for ip, v := range rl.visitors {
				if time.Since(v.lastSeen) > rl.window {
					delete(rl.visitors, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// RateLimit 速率限制中间件
func RateLimit(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !limiter.Allow(ip) {
			c.JSON(429, gin.H{"error": "请求过于频繁，请稍后重试"})
			c.Abort()
			return
		}
		c.Next()
	}
}
