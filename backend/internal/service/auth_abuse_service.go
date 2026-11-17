package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	authActionBlock           int64 = 1
	authActionAnomaly         int64 = 2
	ipBlockCacheTTL                 = 30 * time.Second
	ipBlockMissTTL                  = 3 * time.Second
	ipBlockMutationLease            = 10 * time.Second
	ipBlockMutationTimeout          = 2 * time.Second
	authAnomalyReportInterval       = time.Minute
)

var authFailureScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[3]) == 1 then return {0,0,0,0} end
local clock = redis.call('TIME')
local now = tonumber(clock[1])*1000 + math.floor(tonumber(clock[2])/1000)
local seq = redis.call('INCR', KEYS[2])
redis.call('PEXPIRE', KEYS[2], ARGV[2])
redis.call('ZADD', KEYS[1], now, tostring(seq))
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now-tonumber(ARGV[2]))
redis.call('PEXPIRE', KEYS[1], ARGV[2])
local total = redis.call('ZCARD', KEYS[1])
local recent = redis.call('ZCOUNT', KEYS[1], now-tonumber(ARGV[1])+1, '+inf')
if total > tonumber(ARGV[4]) then
 redis.call('ZREMRANGEBYRANK', KEYS[1], 0, total-tonumber(ARGV[4])-1)
end
local action = 0
if recent >= tonumber(ARGV[3]) or total >= tonumber(ARGV[4]) then
 if ARGV[8] == '1' and redis.call('SET', KEYS[4], ARGV[5], 'NX', 'PX', ARGV[9]) then action = 2 end
 if ARGV[7] == '1' and redis.call('SET', KEYS[3], ARGV[5], 'NX', 'PX', ARGV[6]) then action = action+1 end
end
return {action,total,recent,now}
`)

var releaseIPBlockLeaseScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end
return 0
`)

// AuthAbuseService 统一维护跨账号失败窗口及持久封禁，Redis 计数在多实例间共享。
type AuthAbuseService struct {
	repo      IPBlockRepository
	redis     *redis.Client
	cfg       config.AuthAbuseConfig
	whitelist *ip.CompiledIPRules
}

// NewAuthAbuseService 复用数据库仓储和 Redis，不启动后台扫描或修改现有账号。
func NewAuthAbuseService(repo IPBlockRepository, redisClient *redis.Client, cfg *config.Config) *AuthAbuseService {
	settings := cfg.Security.AuthAbuse
	return &AuthAbuseService{repo: repo, redis: redisClient, cfg: settings, whitelist: ip.CompileIPRules(settings.Whitelist)}
}

// Settings 返回当前自动防护配置，白名单不向页面公开。
func (s *AuthAbuseService) Settings() config.AuthAbuseConfig { return s.cfg }

// NormalizeAuthIP 验证并规范化单个 IP，不把主机名、端口或网段当作访客地址。
func NormalizeAuthIP(value string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || addr.Zone() != "" {
		return "", infraerrors.BadRequest("INVALID_CLIENT_IP", "请输入有效的单个 IP 地址")
	}
	return addr.Unmap().String(), nil
}

// exempt 只跳过管理员明确配置的可信白名单，不默认豁免整个代理或私网。
func (s *AuthAbuseService) exempt(addr string) bool {
	allowed, _ := ip.CheckIPRestrictionWithCompiledRules(addr, s.whitelist, nil)
	return s.whitelist.PatternCount > 0 && allowed
}

// authIPKeys 将同一 IP 的 Redis 键置于相同哈希槽，支持原子脚本。
func authIPKeys(addr string) (string, string, string, string) {
	prefix := "auth-abuse:{" + addr + "}:"
	return prefix + "block", prefix + "failures", prefix + "sequence", prefix + "mutation"
}

// Check 在任何业务或鉴权查询前读取名单；依赖故障交由入口显式拒绝，不静默放行。
func (s *AuthAbuseService) Check(ctx context.Context, value string) (*IPBlock, error) {
	addr, err := NormalizeAuthIP(value)
	if err != nil {
		return nil, err
	}
	if s.exempt(addr) {
		return nil, nil
	}
	cacheKey, _, _, leaseKey := authIPKeys(addr)
	valueJSON, err := s.redis.Get(ctx, cacheKey).Result()
	if errors.Is(err, redis.Nil) {
		b, findErr := s.repo.Find(ctx, addr)
		if findErr != nil {
			return nil, fmt.Errorf("read IP block: %w", findErr)
		}
		if !b.IsActive(time.Now()) {
			b = nil
		}
		encoded, marshalErr := json.Marshal(b)
		if marshalErr != nil {
			return nil, marshalErr
		}
		ttl := ipBlockCacheTTL
		if b == nil {
			ttl = ipBlockMissTTL
		}
		// NX 防止并发的旧查询覆盖管理员刚写入的封禁结果。
		if err := s.redis.SetNX(ctx, cacheKey, string(encoded), ttl).Err(); err != nil {
			return nil, err
		}
		valueJSON, err = s.redis.Get(ctx, cacheKey).Result()
	}
	if err != nil {
		return nil, fmt.Errorf("read IP block cache: %w", err)
	}
	var b *IPBlock
	if err := json.Unmarshal([]byte(valueJSON), &b); err != nil {
		return nil, fmt.Errorf("invalid IP block cache: %w", err)
	}
	if b.IsActive(time.Now()) {
		return b, nil
	}
	// 名单变更尚未持久化完成时不进入密码验证或上游转发。
	mutating, err := s.redis.Exists(ctx, leaseKey).Result()
	if err != nil {
		return nil, err
	}
	if mutating > 0 {
		return nil, infraerrors.ServiceUnavailable("IP_PROTECTION_BUSY", "IP 防护状态正在更新，请稍后重试")
	}
	return nil, nil
}

// cacheBlock 发布持久化结果，所有实例下一次请求均读取共享缓存。
func (s *AuthAbuseService) cacheBlock(ctx context.Context, addr string, b *IPBlock) error {
	encoded, err := json.Marshal(b)
	if err != nil {
		return err
	}
	key, _, _, _ := authIPKeys(addr)
	return s.redis.Set(ctx, key, string(encoded), ipBlockCacheTTL).Err()
}

// releaseLease 只释放本次操作的租约，不删除其他实例已获得的锁。
func (s *AuthAbuseService) releaseLease(ctx context.Context, key, token string) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	// 释放失败时租约仍会按固定期限过期；错误不影响已保存的封禁。
	if err := releaseIPBlockLeaseScript.Run(cleanupCtx, s.redis, []string{key}, token).Err(); err != nil {
		// 通过返回路径以外的结构化日志暴露 Redis 故障。
		slog.Warn("release IP protection lease failed", "error", err)
	}
}

// RecordFailure 只接收明确的认证失败事件；成功请求不清除 IP 的失败历史。
func (s *AuthAbuseService) RecordFailure(ctx context.Context, value, reason string, details ...AuthFailureDetails) (*IPBlock, error) {
	if !s.cfg.Enabled && !s.cfg.DetectionEnabled {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, ipBlockMutationTimeout)
	defer cancel()
	addr, err := NormalizeAuthIP(value)
	if err != nil {
		return nil, err
	}
	if s.exempt(addr) {
		return nil, nil
	}
	_, failuresKey, sequenceKey, leaseKey := authIPKeys(addr)
	token := uuid.NewString()
	autoEnabled, detectionEnabled := 0, 0
	// 已封禁请求仅更新异常摘要，不再次处罚或占用名单变更租约。
	if s.cfg.Enabled && reason != "client_ip_blocked" {
		autoEnabled = 1
	}
	if s.cfg.DetectionEnabled {
		detectionEnabled = 1
	}
	result, err := authFailureScript.Run(ctx, s.redis, []string{failuresKey, sequenceKey, leaseKey, authAnomalyReportKey(addr)},
		s.cfg.ShortWindowSeconds*1000, s.cfg.LongWindowSeconds*1000, s.cfg.ShortThreshold, s.cfg.LongThreshold, token, ipBlockMutationLease.Milliseconds(),
		autoEnabled, detectionEnabled, authAnomalyReportInterval.Milliseconds()).Int64Slice()
	if err != nil {
		return nil, fmt.Errorf("record authentication failure: %w", err)
	}
	if len(result) != 4 {
		return nil, fmt.Errorf("unexpected authentication counter response")
	}
	if result[0] == 0 {
		return nil, nil
	}
	var item *AuthIPAnomaly
	if result[0]&authActionAnomaly != 0 {
		item = &AuthIPAnomaly{ClientIP: addr, Reason: reason, ShortFailures: int(result[2]), LongFailures: int(result[1]),
			ShortWindowSeconds: s.cfg.ShortWindowSeconds, LongWindowSeconds: s.cfg.LongWindowSeconds, LastDetectedAt: time.UnixMilli(result[3]).UTC()}
		if len(details) > 0 {
			meta := details[0]
			if meta.UserID > 0 {
				item.UserID = &meta.UserID
			}
			if meta.APIKeyID > 0 {
				item.APIKeyID = &meta.APIKeyID
			}
			item.PeerIP = meta.PeerIP
			item.ClientIPSource = meta.ClientIPSource
			item.Method = meta.Method
			item.Route = meta.Route
		}
	}
	if result[0]&authActionBlock == 0 {
		if err := s.repo.RecordAnomaly(ctx, item); err != nil {
			return nil, fmt.Errorf("persist authentication anomaly: %w", err)
		}
		return nil, nil
	}
	// 持久化或缓存发布失败时保留短租约，阻止旧的无封禁缓存暂时放行。
	completed := false
	defer func() {
		if completed {
			s.releaseLease(ctx, leaseKey, token)
		}
	}()
	b, changed, err := s.repo.BlockAutomatic(ctx, addr, reason, int(result[1]), s.cfg)
	if err != nil {
		return nil, fmt.Errorf("persist automatic IP block: %w", err)
	}
	if b == nil {
		return nil, fmt.Errorf("automatic IP block returned no record")
	}
	if err := s.cacheBlock(ctx, addr, b); err != nil {
		return nil, fmt.Errorf("IP block saved but cache publication failed: %w", err)
	}
	completed = true
	// 优先完成封禁，摘要写入故障不会弱化已有的自动处罚或使其审计丢失。
	if item != nil {
		if err := s.repo.RecordAnomaly(ctx, item); err != nil {
			slog.Error("authentication anomaly persistence failed", "error", err)
		}
	}
	if !changed {
		return nil, nil
	}
	return b, nil
}

// withMutationLock 串行化手动与自动名单变更，避免解封后被旧的并发操作再次封禁。
func (s *AuthAbuseService) withMutationLock(ctx context.Context, addr string, operation func(context.Context) (*IPBlock, error)) (*IPBlock, error) {
	ctx, cancel := context.WithTimeout(ctx, ipBlockMutationTimeout)
	defer cancel()
	_, _, _, key := authIPKeys(addr)
	token := uuid.NewString()
	locked, err := s.redis.SetNX(ctx, key, token, ipBlockMutationLease).Result()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, infraerrors.Conflict("IP_PROTECTION_BUSY", "该 IP 状态正在更新，请稍后重试")
	}
	b, err := operation(ctx)
	if err == nil {
		s.releaseLease(ctx, key, token)
	}
	// 失败后等待租约自然到期，入口会明确返回临时不可用。
	return b, err
}

// BlockManual 保存临时或永久封禁；秒数为零代表永久。
func (s *AuthAbuseService) BlockManual(ctx context.Context, value, reason string, seconds int, actor int64) (*IPBlock, error) {
	if seconds != 0 && (seconds < 60 || seconds > 2592000) {
		return nil, infraerrors.BadRequest("INVALID_BLOCK_DURATION", "封禁时长无效")
	}
	if strings.TrimSpace(reason) == "" || len([]rune(reason)) > 128 || actor <= 0 {
		return nil, infraerrors.BadRequest("INVALID_BLOCK_REQUEST", "封禁原因或管理员身份无效")
	}
	addr, err := NormalizeAuthIP(value)
	if err != nil {
		return nil, err
	}
	if s.exempt(addr) {
		return nil, infraerrors.BadRequest("IP_WHITELISTED", "该 IP 位于防护白名单，请先调整配置")
	}
	return s.withMutationLock(ctx, addr, func(ctx context.Context) (*IPBlock, error) {
		b, err := s.repo.BlockManual(ctx, addr, reason, seconds, actor)
		if err != nil {
			return nil, err
		}
		if err := s.cacheBlock(ctx, addr, b); err != nil {
			return nil, infraerrors.ServiceUnavailable("IP_BLOCK_CACHE_SYNC_FAILED", "封禁已保存，但缓存同步失败，请刷新名单并重试").WithCause(err)
		}
		return b, nil
	})
}

// Unblock 保留数据库历史，并原子清除旧失败窗口，避免解封后立即重封。
func (s *AuthAbuseService) Unblock(ctx context.Context, id int64) (*IPBlock, error) {
	b, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, infraerrors.NotFound("IP_BLOCK_NOT_FOUND", "封禁记录不存在")
	}
	return s.withMutationLock(ctx, b.ClientIP, func(ctx context.Context) (*IPBlock, error) {
		b, err := s.repo.Revoke(ctx, id)
		if err != nil {
			return nil, err
		}
		key, failuresKey, sequenceKey, _ := authIPKeys(b.ClientIP)
		pipe := s.redis.TxPipeline()
		pipe.Del(ctx, failuresKey, sequenceKey)
		pipe.Del(ctx, authAnomalyReportKey(b.ClientIP))
		pipe.Set(ctx, key, "null", ipBlockMissTTL)
		if _, err := pipe.Exec(ctx); err != nil {
			return nil, infraerrors.ServiceUnavailable("IP_UNBLOCK_CACHE_SYNC_FAILED", "解封已保存，但缓存同步失败，请刷新名单并重试").WithCause(err)
		}
		return b, nil
	})
}

// List 分页查询封禁名单，页大小由处理器限制。
func (s *AuthAbuseService) List(ctx context.Context, page, size int, activeOnly bool) ([]*IPBlock, int64, error) {
	return s.repo.List(ctx, page, size, activeOnly)
}

// authAnomalyReportKey 在同一 IP 哈希槽中限制数据库摘要更新频率，不影响请求准入。
func authAnomalyReportKey(addr string) string { return "auth-abuse:{" + addr + "}:anomaly-report" }

// ListAnomalies 返回检测摘要，窗口次数是保留样本的下界，列表不暴露凭证。
func (s *AuthAbuseService) ListAnomalies(ctx context.Context, filter AuthIPAnomalyFilter) ([]*AuthIPAnomaly, int64, error) {
	return s.repo.ListAnomalies(ctx, filter)
}

// DismissAnomaly 保留检测历史并清空旧失败窗口，后续新增试错达到阈值时再次提醒。
func (s *AuthAbuseService) DismissAnomaly(ctx context.Context, id, actor int64) (*AuthIPAnomaly, error) {
	if id <= 0 || actor <= 0 {
		return nil, infraerrors.BadRequest("INVALID_ANOMALY_REQUEST", "异常记录或管理员身份无效")
	}
	item, err := s.repo.GetAnomaly(ctx, id)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, infraerrors.NotFound("IP_ANOMALY_NOT_FOUND", "异常记录不存在")
	}
	var dismissed *AuthIPAnomaly
	_, err = s.withMutationLock(ctx, item.ClientIP, func(ctx context.Context) (*IPBlock, error) {
		block, err := s.repo.Find(ctx, item.ClientIP)
		if err != nil {
			return nil, err
		}
		if block.IsActive(time.Now()) {
			return nil, infraerrors.Conflict("IP_ALREADY_BLOCKED", "该 IP 正在封禁中，请在封禁名单管理")
		}
		dismissed, err = s.repo.DismissAnomaly(ctx, id, actor)
		if err != nil {
			return nil, err
		}
		_, failures, sequence, _ := authIPKeys(item.ClientIP)
		if err := s.redis.Del(ctx, failures, sequence, authAnomalyReportKey(item.ClientIP)).Err(); err != nil {
			return nil, infraerrors.ServiceUnavailable("IP_ANOMALY_CACHE_SYNC_FAILED", "忽略已保存，但计数同步失败，请刷新后重试").WithCause(err)
		}
		return nil, nil
	})
	return dismissed, err
}
