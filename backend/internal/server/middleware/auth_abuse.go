package middleware

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

const authFailureReasonKey = "auth_abuse_failure_reason"
const authFailureUserIDKey = "auth_abuse_verified_user_id"
const authAbuseServiceKey = "auth_abuse_service"
const authProtectionTimeout = 2 * time.Second

// MarkAuthFailure 标记明确的登录失败事件，由统一入口中间件在请求结束时计数。
func MarkAuthFailure(c *gin.Context, reason string) { c.Set(authFailureReasonKey, reason) }

// MarkAuthFailureForUser 仅关联已验证的用户 ID，禁止根据攻击者提交的账号推断身份。
func MarkAuthFailureForUser(c *gin.Context, reason string, userID int64) {
	MarkAuthFailure(c, reason)
	if userID > 0 {
		c.Set(authFailureUserIDKey, userID)
	}
}

// authFailureDetails 汇总可信解析来源与最近已识别身份，不采集认证请求体或 Key 值。
func authFailureDetails(c *gin.Context) service.AuthFailureDetails {
	resolution := ip.GetClientIPResolution(c)
	details := service.AuthFailureDetails{PeerIP: resolution.PeerIP, ClientIPSource: normalizePersistentText(resolution.Source, 128),
		Method: normalizePersistentText(c.Request.Method, 16), Route: normalizePersistentText(c.FullPath(), 512), UserID: c.GetInt64(authFailureUserIDKey)}
	key, ok := GetAPIKeyFromContext(c)
	if !ok || key == nil {
		key, ok = GetOpsFallbackAPIKey(c)
	}
	if ok && key != nil {
		details.APIKeyID = key.ID
		if key.User != nil {
			details.UserID = key.User.ID
		}
	}
	if details.UserID == 0 {
		if subject, ok := GetAuthSubjectFromContext(c); ok {
			details.UserID = subject.UserID
		}
	}
	return details
}

// CheckAuthIP 为已建立的长连接在新任务开始前复核封禁状态，复用请求入口固定的 IP。
func CheckAuthIP(c *gin.Context) error {
	value, ok := c.Get(authAbuseServiceKey)
	if !ok {
		return nil
	}
	svc, ok := value.(*service.AuthAbuseService)
	if !ok || svc == nil {
		return infraerrors.ServiceUnavailable("IP_PROTECTION_UNAVAILABLE", "IP protection unavailable")
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), authProtectionTimeout)
	defer cancel()
	b, err := svc.Check(ctx, SecurityClientIP(c))
	if err != nil {
		return err
	}
	if b != nil {
		return infraerrors.Forbidden("IP_BLOCKED", "IP is blocked")
	}
	return nil
}

// AuthAbuseGuard 在鉴权之前拦截封禁 IP，并统一收集登录与网关认证失败。
func AuthAbuseGuard(svc *service.AuthAbuseService, audit *service.AuditLogService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 静态页面和健康探针保持可读；封禁限制所有业务入口，OPTIONS 不进行业务处理。
		if c.Request.Method == http.MethodOptions || !authProtectionPath(c.FullPath()) {
			c.Next()
			return
		}
		clientIP := SecurityClientIP(c)
		ctx, cancel := context.WithTimeout(c.Request.Context(), authProtectionTimeout)
		block, err := svc.Check(ctx, clientIP)
		cancel()
		if err != nil {
			MarkIngressRejected(c, IngressRejectIPProtectionUnavailable)
			if infraerrors.Reason(err) != "IP_PROTECTION_BUSY" {
				slog.Warn("IP protection check failed", "error", err)
			}
			abortAuthProtection(c, http.StatusServiceUnavailable, "IP_PROTECTION_UNAVAILABLE", "IP 防护暂时不可用，请稍后重试")
			return
		}
		if block != nil {
			MarkIngressRejected(c, IngressRejectIPBlocked)
			if block.ExpiresAt != nil {
				seconds := int(math.Ceil(time.Until(*block.ExpiresAt).Seconds()))
				if seconds < 1 {
					seconds = 1
				}
				c.Header("Retry-After", strconv.Itoa(seconds))
			}
			abortAuthProtection(c, http.StatusForbidden, "IP_BLOCKED", "当前 IP 已被封禁，请联系管理员")
			ctx, cancel = context.WithTimeout(context.WithoutCancel(c.Request.Context()), authProtectionTimeout)
			_, err = svc.RecordFailure(ctx, clientIP, string(IngressRejectIPBlocked), authFailureDetails(c))
			cancel()
			if err != nil {
				slog.Error("blocked IP anomaly accounting failed", "error", err)
			}
			return
		}
		c.Set(authAbuseServiceKey, svc)
		c.Next()
		reason := c.GetString(authFailureReasonKey)
		if reason == "" {
			if ingressReason, ok := GetIngressRejectReason(c); ok {
				switch ingressReason {
				case IngressRejectAPIKeyRequired, IngressRejectInvalidAPIKey, IngressRejectAPIKeyDisabled, IngressRejectUserInactive, IngressRejectIPRestricted, IngressRejectInvalidAuthRateLimited:
					reason = string(ingressReason)
				}
			}
		}
		if reason == "" {
			return
		}
		// 客户端断开不能取消已发生的失败事件；计数与持久化使用有界的独立上下文。
		ctx, cancel = context.WithTimeout(context.WithoutCancel(c.Request.Context()), authProtectionTimeout)
		defer cancel()
		block, err = svc.RecordFailure(ctx, clientIP, reason, authFailureDetails(c))
		if err != nil {
			slog.Error("authentication abuse accounting failed", "error", err)
			return
		}
		if block == nil {
			return
		}
		resolution := ip.GetClientIPResolution(c)
		audit.Record(&service.AuditLog{
			Action: "security.ip.auto_block", Method: c.Request.Method, Path: c.FullPath(), ClientIP: clientIP, StatusCode: c.Writer.Status(),
			RequestID: c.Writer.Header().Get("X-Request-ID"), UserAgent: c.Request.UserAgent(),
			Extra: map[string]any{"peer_ip": resolution.PeerIP, "client_ip_source": resolution.Source, "reason": reason,
				"failure_count": block.FailureCount, "strike_count": block.StrikeCount, "expires_at": block.ExpiresAt, "block_id": block.ID},
		})
	}
}

// authProtectionPath 保护全部已注册业务路由，避免新增根路径别名时遗漏封禁检查。
// 静态页面没有匹配的业务路由，健康和安装状态探针显式豁免。
func authProtectionPath(path string) bool {
	switch path {
	case "", "/health", "/setup/status":
		return false
	default:
		return true
	}
}

// abortAuthProtection 保留面板和 Gemini SDK 使用的错误响应格式。
func abortAuthProtection(c *gin.Context, status int, code, message string) {
	if strings.Contains(c.Request.URL.Path, "/v1beta") {
		abortWithGoogleError(c, status, message)
		return
	}
	if strings.HasPrefix(c.Request.URL.Path, "/api/v1/") {
		response.ErrorWithDetails(c, status, message, code, nil)
		c.Abort()
		return
	}
	AbortWithError(c, status, code, message)
}
