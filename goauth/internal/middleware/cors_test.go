package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func newCORSRouter(allowOrigins []string) *gin.Engine {
	router := gin.New()
	router.Use(CORS(allowOrigins))
	router.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})
	return router
}

func TestCORS_ExactOriginAllowsCredentials(t *testing.T) {
	router := newCORSRouter([]string{"https://app.example.com"})

	req := httptest.NewRequest("GET", "/ping", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
}

func TestCORS_WildcardNoCredentials(t *testing.T) {
	router := newCORSRouter([]string{"*"})

	req := httptest.NewRequest("GET", "/ping", nil)
	req.Header.Set("Origin", "https://random.example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"), "通配符放行时不得携带凭据")
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	router := newCORSRouter([]string{"https://app.example.com"})

	req := httptest.NewRequest("GET", "/ping", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_EmptyOrigins(t *testing.T) {
	router := newCORSRouter([]string{})

	req := httptest.NewRequest("GET", "/ping", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_Preflight(t *testing.T) {
	router := newCORSRouter([]string{"https://app.example.com"})

	req := httptest.NewRequest("OPTIONS", "/ping", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
}
