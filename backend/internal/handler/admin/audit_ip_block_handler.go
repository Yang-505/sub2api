package admin

import (
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// ListIPBlocks 分页查询名单及当前自动防护配置，仅管理员可见。
func (h *AuditLogHandler) ListIPBlocks(c *gin.Context) {
	page, size := response.ParsePagination(c)
	if size > 100 {
		size = 100
	}
	items, total, err := h.authAbuseService.List(c.Request.Context(), page, size, c.Query("active_only") != "false")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"items": items, "total": total, "page": page, "page_size": size, "config": h.authAbuseService.Settings()})
}

// BlockIP 创建或更新封禁；避免管理员误封当前来源、机器凭证批量封禁及非法地址。
func (h *AuditLogHandler) BlockIP(c *gin.Context) {
	if _, machine := middleware.MachineCredentialReason(c); machine {
		response.Forbidden(c, "IP 封禁需要管理员浏览器会话")
		return
	}
	var req struct {
		ClientIP        string `json:"client_ip" binding:"required"`
		Reason          string `json:"reason" binding:"required,max=128"`
		DurationSeconds int    `json:"duration_seconds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "封禁参数无效")
		return
	}
	if req.DurationSeconds != 0 && (req.DurationSeconds < 60 || req.DurationSeconds > 2592000) {
		response.BadRequest(c, "临时封禁时长应在 60 秒至 30 天之间")
		return
	}
	addr, err := service.NormalizeAuthIP(strings.TrimSpace(req.ClientIP))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if addr == middleware.SecurityClientIP(c) {
		response.BadRequest(c, "不能封禁当前管理员使用的 IP")
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		response.BadRequest(c, "请填写封禁原因")
		return
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 {
		response.Unauthorized(c, "管理员身份无效")
		return
	}
	b, err := h.authAbuseService.BlockManual(c.Request.Context(), addr, reason, req.DurationSeconds, subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	expires := "permanent"
	if b.ExpiresAt != nil {
		expires = b.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	middleware.SetAuditExtra(c, map[string]any{"target_ip": addr, "block_id": b.ID, "expires_at": expires})
	response.Success(c, b)
}

// UnblockIP 解除指定记录的封禁并清除旧失败窗口，保留解封审计。
func (h *AuditLogHandler) UnblockIP(c *gin.Context) {
	if _, machine := middleware.MachineCredentialReason(c); machine {
		response.Forbidden(c, "IP 解封需要管理员浏览器会话")
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "封禁记录 ID 无效")
		return
	}
	b, err := h.authAbuseService.Unblock(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	middleware.SetAuditExtra(c, map[string]any{"target_ip": b.ClientIP, "block_id": b.ID})
	response.Success(c, gin.H{"unblocked": true})
}
