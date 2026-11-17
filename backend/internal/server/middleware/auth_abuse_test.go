//go:build unit

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// TestAuthProtectionMatchedRoutes 确认全局中间件可读取匹配路由，根路径别名不会绕过防护。
func TestAuthProtectionMatchedRoutes(t *testing.T) {
	router := gin.New()
	protected := false
	router.Use(func(c *gin.Context) {
		protected = authProtectionPath(c.FullPath())
		c.Next()
	})
	for _, path := range []string{"/api/v1/auth/login", "/chat/completions", "/images/tasks/:task_id", "/realtime", "/future-api", "/health", "/setup/status"} {
		router.GET(path, func(c *gin.Context) { c.Status(http.StatusOK) })
	}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/api/v1/auth/login", true}, {"/chat/completions", true}, {"/images/tasks/123", true},
		{"/realtime", true}, {"/future-api", true}, {"/health", false}, {"/setup/status", false}, {"/assets/app.js", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.path, nil))
			require.Equal(t, tc.want, protected)
		})
	}
}

// TestAuthFailureDetailsRejectsSubmittedIdentity 确认提交的账号名不能成为关联用户身份。
func TestAuthFailureDetailsRejectsSubmittedIdentity(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"root@example.invalid","password":"invalid-test-value"}`))
	c.Request.RemoteAddr = "203.0.113.42:12345"
	MarkAuthFailure(c, "invalid_credentials")
	details := authFailureDetails(c)
	require.Zero(t, details.UserID)
	require.Zero(t, details.APIKeyID)
	MarkAuthFailureForUser(c, "user_inactive", 7)
	details = authFailureDetails(c)
	require.Equal(t, int64(7), details.UserID)
}

type authAnomalyGuardRepository struct {
	service.IPBlockRepository
	anomaly *service.AuthIPAnomaly
}

// Find 模拟没有现存封禁，隔离真实业务数据库。
func (r *authAnomalyGuardRepository) Find(context.Context, string) (*service.IPBlock, error) {
	return nil, nil
}

// RecordAnomaly 捕获入口计数达到阈值后实际写入的摘要。
func (r *authAnomalyGuardRepository) RecordAnomaly(_ context.Context, item *service.AuthIPAnomaly) error {
	copy := *item
	r.anomaly = &copy
	return nil
}

// TestAuthAbuseGuardCountsRejectedCredentials 覆盖真实鉴权入口到阈值摘要的链路及正常过期排除。
func TestAuthAbuseGuardCountsRejectedCredentials(t *testing.T) {
	for _, tc := range []struct {
		name, auth, reason string
		admin, rateLimited bool
		status             int
	}{
		{name: "invalid user token", auth: "invalid", reason: "invalid_token", status: http.StatusUnauthorized},
		{name: "invalid admin token", auth: "invalid", reason: "invalid_token", admin: true, status: http.StatusUnauthorized},
		{name: "expired user token", auth: "expired", status: http.StatusUnauthorized},
		{name: "expired admin token", auth: "expired", admin: true, status: http.StatusUnauthorized},
		{name: "scoped key guessing", auth: "scoped", reason: "invalid_api_key", admin: true, status: http.StatusUnauthorized},
		{name: "continued gateway abuse", reason: "invalid_auth_rate_limited", rateLimited: true, status: http.StatusTooManyRequests},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{JWT: config.JWTConfig{Secret: "auth-anomaly-test-secret"}, Security: config.SecurityConfig{AuthAbuse: config.AuthAbuseConfig{
				DetectionEnabled: true, ShortWindowSeconds: 900, ShortThreshold: 10, LongWindowSeconds: 86400, LongThreshold: 30,
			}}}
			server := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: server.Addr(), MaxRetries: -1})
			t.Cleanup(func() { _ = client.Close() })
			repo := &authAnomalyGuardRepository{}
			authService := service.NewAuthService(nil, nil, nil, nil, cfg, nil, nil, nil, nil, nil, nil, nil, nil)
			token := "invalid"
			if tc.auth == "expired" {
				claims := service.JWTClaims{RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour))}}
				var err error
				token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(cfg.JWT.Secret))
				require.NoError(t, err)
			}
			router := gin.New()
			router.Use(AuthAbuseGuard(service.NewAuthAbuseService(repo, client, cfg), nil))
			if tc.admin {
				router.Use(adminAuth(authService, &service.UserService{}, &service.SettingService{}, nil))
			} else if !tc.rateLimited {
				router.Use(jwtAuth(authService, nil, nil, nil, nil))
			}
			router.GET("/protected", func(c *gin.Context) {
				if tc.rateLimited {
					MarkIngressRejected(c, IngressRejectInvalidAuthRateLimited)
					c.AbortWithStatus(http.StatusTooManyRequests)
					return
				}
				c.Status(http.StatusOK)
			})
			for i := 0; i < 10; i++ {
				req := httptest.NewRequest(http.MethodGet, "/protected", nil)
				req.RemoteAddr = "203.0.113.42:12345"
				if tc.auth == "scoped" {
					req.Header.Set("x-api-key", "adm_sc_invalid")
				} else {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				response := httptest.NewRecorder()
				router.ServeHTTP(response, req)
				require.Equal(t, tc.status, response.Code)
				if i < 9 {
					require.Nil(t, repo.anomaly)
				}
			}
			if tc.reason == "" {
				require.Nil(t, repo.anomaly)
			} else {
				require.NotNil(t, repo.anomaly)
				require.Equal(t, tc.reason, repo.anomaly.Reason)
				require.Equal(t, 10, repo.anomaly.ShortFailures)
				require.Nil(t, repo.anomaly.UserID)
				require.Nil(t, repo.anomaly.APIKeyID)
			}
		})
	}
}
