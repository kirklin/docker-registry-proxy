package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestProxyHandler(t *testing.T) {
	// 设置测试路由
	RegistryRoutes = map[string]string{
		"docker.example.com": dockerHub,
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Any("/*path", ProxyHandler)

	// 测试 /v2/ 端点
	req, _ := http.NewRequest("GET", "/v2/", nil)
	req.Host = "docker.example.com"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Header().Get("Www-Authenticate"), "docker.example.com/v2/auth")

	// 可以添加更多测试用例...
}
