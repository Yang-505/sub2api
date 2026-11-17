package service

import (
	"context"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

// IPBlock 保存单个 IP 的封禁和升级历史；到期时间为空表示永久封禁。
type IPBlock struct {
	ID           int64      `json:"id"`
	ClientIP     string     `json:"client_ip"`
	Reason       string     `json:"reason"`
	Source       string     `json:"source"`
	FailureCount int        `json:"failure_count"`
	StrikeCount  int        `json:"strike_count"`
	ActorUserID  *int64     `json:"actor_user_id,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	Active       bool       `json:"active"`
}

// IsActive 按当前时间判断封禁是否有效，防止缓存延长已到期的封禁。
func (b *IPBlock) IsActive(now time.Time) bool {
	return b != nil && b.RevokedAt == nil && (b.ExpiresAt == nil || b.ExpiresAt.After(now))
}

// IPBlockRepository 提供封禁名单和检测摘要持久化，不依赖操作日志扫描。
type IPBlockRepository interface {
	Find(context.Context, string) (*IPBlock, error)
	Get(context.Context, int64) (*IPBlock, error)
	List(context.Context, int, int, bool) ([]*IPBlock, int64, error)
	BlockAutomatic(context.Context, string, string, int, config.AuthAbuseConfig) (*IPBlock, bool, error)
	BlockManual(context.Context, string, string, int, int64) (*IPBlock, error)
	Revoke(context.Context, int64) (*IPBlock, error)
	RecordAnomaly(context.Context, *AuthIPAnomaly) error
	GetAnomaly(context.Context, int64) (*AuthIPAnomaly, error)
	ListAnomalies(context.Context, AuthIPAnomalyFilter) ([]*AuthIPAnomaly, int64, error)
	DismissAnomaly(context.Context, int64, int64) (*AuthIPAnomaly, error)
}

// AuthFailureDetails 仅保存已识别的身份和可信 IP 来源，不保存提交的账号、密码或凭证。
type AuthFailureDetails struct {
	UserID         int64
	APIKeyID       int64
	PeerIP         string
	ClientIPSource string
	Method         string
	Route          string
}

// AuthIPAnomaly 保存达到失败阈值的 IP 摘要；身份是最近一次可识别的用户或 Key。
type AuthIPAnomaly struct {
	ID                 int64      `json:"id"`
	ClientIP           string     `json:"client_ip"`
	Reason             string     `json:"reason"`
	ShortFailures      int        `json:"short_failures"`
	LongFailures       int        `json:"long_failures"`
	ShortWindowSeconds int        `json:"short_window_seconds"`
	LongWindowSeconds  int        `json:"long_window_seconds"`
	UserID             *int64     `json:"user_id"`
	UserEmail          string     `json:"user_email"`
	APIKeyID           *int64     `json:"api_key_id"`
	PeerIP             string     `json:"peer_ip"`
	ClientIPSource     string     `json:"client_ip_source"`
	Method             string     `json:"method"`
	Route              string     `json:"route"`
	FirstDetectedAt    time.Time  `json:"first_detected_at"`
	LastDetectedAt     time.Time  `json:"last_detected_at"`
	DismissedAt        *time.Time `json:"dismissed_at"`
	BlockID            *int64     `json:"block_id"`
	Blocked            bool       `json:"blocked"`
}

// AuthIPAnomalyFilter 限制异常列表分页和可识别用户、IP、处理状态筛选。
type AuthIPAnomalyFilter struct {
	Page     int
	Size     int
	Status   string
	ClientIP string
	UserID   int64
}
