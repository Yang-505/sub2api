package admin

import (
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// ListIPAnomalies 分页展示持续认证失败来源，筛选身份仅使用已识别的用户 ID。
func (h *AuditLogHandler) ListIPAnomalies(c *gin.Context) {
	page, size := response.ParsePagination(c)
	if size > 100 {
		size = 100
	}
	filter := service.AuthIPAnomalyFilter{Page: page, Size: size, Status: c.DefaultQuery("status", "pending")}
	switch filter.Status {
	case "pending", "dismissed", "blocked", "all":
	default:
		response.BadRequest(c, "异常处理状态无效")
		return
	}
	if value := strings.TrimSpace(c.Query("client_ip")); value != "" {
		addr, err := service.NormalizeAuthIP(value)
		if err != nil {
			response.ErrorFrom(c, err)
			return
		}
		filter.ClientIP = addr
	}
	if value := strings.TrimSpace(c.Query("user_id")); value != "" {
		id, err := strconv.ParseInt(value, 10, 64)
		if err != nil || id <= 0 {
			response.BadRequest(c, "关联用户 ID 无效")
			return
		}
		filter.UserID = id
	}
	items, total, err := h.authAbuseService.ListAnomalies(c.Request.Context(), filter)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"items": items, "total": total, "page": page, "page_size": size, "config": h.authAbuseService.Settings()})
}

// DismissIPAnomaly 允许管理员浏览器会话忽略提醒，保持后续重新检测能力。
func (h *AuditLogHandler) DismissIPAnomaly(c *gin.Context) {
	if _, machine := middleware.MachineCredentialReason(c); machine {
		response.Forbidden(c, "忽略异常需要管理员浏览器会话")
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "异常记录 ID 无效")
		return
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 {
		response.Unauthorized(c, "管理员身份无效")
		return
	}
	item, err := h.authAbuseService.DismissAnomaly(c.Request.Context(), id, subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	middleware.SetAuditExtra(c, map[string]any{"target_ip": item.ClientIP, "anomaly_id": item.ID})
	response.Success(c, gin.H{"dismissed": true})
}
