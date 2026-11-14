package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRequestTimeout_ContextCancelled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestTimeout(50 * time.Millisecond))
	r.GET("/slow", func(c *gin.Context) {
		<-c.Request.Context().Done()
		c.String(http.StatusServiceUnavailable, "timeout")
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/slow", nil))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestRequestTimeout_Disabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestTimeout(0))
	called := false
	r.GET("/ok", func(c *gin.Context) {
		called = true
		c.String(http.StatusOK, "ok")
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/ok", nil))
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}
