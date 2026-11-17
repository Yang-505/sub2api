//go:build unit

package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// TestLogin2FAContinuedAttemptsMarked 确认二次验证限流后的请求仍计入异常，不把未验证账号作为身份。
func TestLogin2FAContinuedAttemptsMarked(t *testing.T) {
	cache := &oauthPendingFlowTotpCacheStub{
		loginSessions:  map[string]*service.TotpLoginSession{"test-session": {UserID: 7}},
		verifyAttempts: map[int64]int{7: 100},
	}
	handler := &AuthHandler{totpService: service.NewTotpService(nil, nil, cache, nil, nil, nil)}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/2fa", strings.NewReader(`{"temp_token":"test-session","totp_code":"000000"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	handler.Login2FA(c)
	require.Equal(t, http.StatusTooManyRequests, recorder.Code)
	require.Equal(t, "second_factor_rate_limited", c.GetString("auth_abuse_failure_reason"))
	require.Equal(t, int64(7), c.GetInt64("auth_abuse_verified_user_id"))
}
