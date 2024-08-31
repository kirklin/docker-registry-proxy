package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// Constants
const (
	dockerHub = "https://registry-1.docker.io"
)

// RegistryRoutes defines the mapping between custom domains and Docker registries
// RegistryRoutes 定义了自定义域名和 Docker 仓库之间的映射
var RegistryRoutes = map[string]string{
	"docker.example.com":     dockerHub,
	"quay.example.com":       "https://quay.io",
	"gcr.example.com":        "https://gcr.io",
	"k8s-gcr.example.com":    "https://k8s.gcr.io",
	"k8s.example.com":        "https://registry.k8s.io",
	"ghcr.example.com":       "https://ghcr.io",
	"cloudsmith.example.com": "https://docker.cloudsmith.io",
	"ecr.example.com":        "https://public.ecr.aws",
}

// ProxyHandler handles all incoming requests and routes them to appropriate handlers
// ProxyHandler 处理所有传入的请求并将它们路由到适当的处理程序
func ProxyHandler(c *gin.Context) {
	upstream := getUpstreamRegistry(c.Request.Host)
	if upstream == "" {
		handleNotFound(c)
		return
	}

	switch c.Request.URL.Path {
	case "/v2/":
		handleV2Request(c, upstream)
	case "/v2/auth":
		handleAuthRequest(c, upstream)
	default:
		if upstream == dockerHub {
			handleDockerHubRequest(c)
		} else {
			forwardRequest(c, upstream)
		}
	}
}

// getUpstreamRegistry returns the upstream registry URL for a given host
// getUpstreamRegistry 返回给定主机的上游注册表 URL
func getUpstreamRegistry(host string) string {
	return RegistryRoutes[host]
}

// handleNotFound responds with a 404 error and lists available routes
// handleNotFound 响应 404 错误并列出可用路由
func handleNotFound(c *gin.Context) {
	c.JSON(http.StatusNotFound, gin.H{
		"routes": RegistryRoutes,
	})
}

// handleV2Request handles requests to the /v2/ endpoint
// handleV2Request 处理对 /v2/ 端点的请求
func handleV2Request(c *gin.Context, upstream string) {
	newURL := upstream + "/v2/"
	resp, err := forwardAuthenticatedRequest(newURL, c.Request)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		handleUnauthorized(c)
		return
	}

	copyResponse(c, resp)
}

// handleUnauthorized sets up the WWW-Authenticate header for unauthorized requests
// handleUnauthorized 为未经授权的请求设置 WWW-Authenticate 标头
func handleUnauthorized(c *gin.Context) {
	realm := fmt.Sprintf("https://%s/v2/auth", c.Request.Host)
	c.Header("Www-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="docker-proxy"`, realm))
	c.JSON(http.StatusUnauthorized, gin.H{"message": "UNAUTHORIZED"})
}

// handleAuthRequest handles authentication requests
// handleAuthRequest 处理身份验证请求
func handleAuthRequest(c *gin.Context, upstream string) {
	resp, err := http.Get(upstream + "/v2/")
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		copyResponse(c, resp)
		return
	}

	authenticateStr := resp.Header.Get("WWW-Authenticate")
	if authenticateStr == "" {
		copyResponse(c, resp)
		return
	}

	wwwAuthenticate := parseAuthenticate(authenticateStr)
	scope := c.Query("scope")

	if scope != "" && upstream == dockerHub {
		scope = expandDockerHubScope(scope)
	}

	tokenResp, err := fetchToken(wwwAuthenticate, scope, c.GetHeader("Authorization"))
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	defer tokenResp.Body.Close()

	copyResponse(c, tokenResp)
}

// expandDockerHubScope expands the scope for Docker Hub official images
// expandDockerHubScope 扩展 Docker Hub 官方镜像的作用域
func expandDockerHubScope(scope string) string {
	parts := strings.Split(scope, ":")
	if len(parts) == 3 && !strings.Contains(parts[1], "/") {
		parts[1] = "library/" + parts[1]
		return strings.Join(parts, ":")
	}
	return scope
}

// handleDockerHubRequest handles requests specific to Docker Hub
// handleDockerHubRequest 处理特定于 Docker Hub 的请求
func handleDockerHubRequest(c *gin.Context) {
	pathParts := strings.Split(c.Request.URL.Path, "/")
	if len(pathParts) == 5 {
		newPath := fmt.Sprintf("/v2/library/%s/%s/%s", pathParts[2], pathParts[3], pathParts[4])
		c.Redirect(http.StatusMovedPermanently, newPath)
		return
	}

	forwardRequest(c, dockerHub)
}

// forwardRequest forwards the request to the upstream registry
// forwardRequest 将请求转发到上游注册表
func forwardRequest(c *gin.Context, upstream string) {
	newURL := upstream + c.Request.URL.Path
	if c.Request.URL.RawQuery != "" {
		newURL += "?" + c.Request.URL.RawQuery
	}

	resp, err := forwardAuthenticatedRequest(newURL, c.Request)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	defer resp.Body.Close()

	copyResponse(c, resp)
}

// forwardAuthenticatedRequest forwards a request with authentication headers
// forwardAuthenticatedRequest 转发带有身份验证标头的请求
func forwardAuthenticatedRequest(url string, originalReq *http.Request) (*http.Response, error) {
	req, err := http.NewRequest(originalReq.Method, url, originalReq.Body)
	if err != nil {
		return nil, err
	}

	// Copy headers from the original request
	for key, values := range originalReq.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return client.Do(req)
}

// copyResponse copies the response from the upstream to the client
// copyResponse 将上游的响应复制到客户端
func copyResponse(c *gin.Context, resp *http.Response) {
	for key, values := range resp.Header {
		for _, value := range values {
			c.Header(key, value)
		}
	}
	c.Status(resp.StatusCode)
	io.Copy(c.Writer, resp.Body)
}

// parseAuthenticate parses the WWW-Authenticate header
// parseAuthenticate 解析 WWW-Authenticate 标头
func parseAuthenticate(authenticateStr string) map[string]string {
	result := make(map[string]string)
	parts := strings.Split(strings.TrimPrefix(authenticateStr, "Bearer "), ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			result[kv[0]] = strings.Trim(kv[1], `"`)
		}
	}
	return result
}

// fetchToken fetches an authentication token from the registry
// fetchToken 从注册表获取身份验证令牌
func fetchToken(wwwAuthenticate map[string]string, scope, authorization string) (*http.Response, error) {
	tokenURL, err := url.Parse(wwwAuthenticate["realm"])
	if err != nil {
		return nil, err
	}

	query := tokenURL.Query()
	if service, ok := wwwAuthenticate["service"]; ok && service != "" {
		query.Set("service", service)
	}
	if scope != "" {
		query.Set("scope", scope)
	}
	tokenURL.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", tokenURL.String(), nil)
	if err != nil {
		return nil, err
	}

	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

	client := &http.Client{}
	return client.Do(req)
}

// go run main.go -port 8080 -domain example.com -routes "docker=https://registry-1.docker.io,custom=https://my-custom-registry.com"
func main() {
	// 添加命令行参数
	var (
		port         string
		domainSuffix string
		routesStr    string
	)
	flag.StringVar(&port, "port", "8080", "Port to run the server on")
	flag.StringVar(&domainSuffix, "domain", "example.com", "Domain suffix for routes")
	flag.StringVar(&routesStr, "routes", "", "Custom routes in format: subdomain1=url1,subdomain2=url2")
	flag.Parse()

	// 处理自定义路由
	if routesStr != "" {
		customRoutes := strings.Split(routesStr, ",")
		for _, route := range customRoutes {
			parts := strings.SplitN(route, "=", 2)
			if len(parts) == 2 {
				RegistryRoutes[parts[0]+"."+domainSuffix] = parts[1]
			}
		}
	}
	// 添加默认域名本身映射到 Docker Hub
	RegistryRoutes[domainSuffix] = dockerHub
	// 如果没有自定义路由，使用默认路由
	RegistryRoutes = map[string]string{
		domainSuffix:                 dockerHub,
		"docker." + domainSuffix:     dockerHub,
		"quay." + domainSuffix:       "https://quay.io",
		"gcr." + domainSuffix:        "https://gcr.io",
		"k8s-gcr." + domainSuffix:    "https://k8s.gcr.io",
		"k8s." + domainSuffix:        "https://registry.k8s.io",
		"ghcr." + domainSuffix:       "https://ghcr.io",
		"cloudsmith." + domainSuffix: "https://docker.cloudsmith.io",
		"ecr." + domainSuffix:        "https://public.ecr.aws",
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.Any("/*path", ProxyHandler)

	log.Printf("Starting Docker registry proxy server on :%s\n", port)
	log.Printf("Available routes: %v\n", RegistryRoutes)
	log.Fatal(r.Run(":" + port))
}
