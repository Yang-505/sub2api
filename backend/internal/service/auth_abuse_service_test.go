//go:build unit

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

type authAbuseTestRepository struct {
	block          *IPBlock
	automaticCalls int
	reads          int
	mutationError  error
	anomaly        *AuthIPAnomaly
	anomalyCalls   int
}

// Find 模拟按 IP 读取持久化名单。
func (r *authAbuseTestRepository) Find(_ context.Context, addr string) (*IPBlock, error) {
	r.reads++
	if r.block != nil && r.block.ClientIP == addr {
		return r.block, nil
	}
	return nil, nil
}

// Get 模拟读取待解封记录。
func (r *authAbuseTestRepository) Get(_ context.Context, id int64) (*IPBlock, error) {
	if r.block != nil && r.block.ID == id {
		return r.block, nil
	}
	return nil, nil
}

// List 模拟管理员名单查询。
func (r *authAbuseTestRepository) List(context.Context, int, int, bool) ([]*IPBlock, int64, error) {
	return nil, 0, nil
}

// BlockAutomatic 捕获实际触发的持久封禁，便于检查长窗口和触发次数。
func (r *authAbuseTestRepository) BlockAutomatic(_ context.Context, addr, reason string, failures int, cfg config.AuthAbuseConfig) (*IPBlock, bool, error) {
	if r.mutationError != nil {
		return nil, false, r.mutationError
	}
	if r.block.IsActive(time.Now()) {
		return r.block, false, nil
	}
	r.automaticCalls++
	expires := time.Now().Add(time.Duration(cfg.InitialBlockSeconds) * time.Second)
	r.block = &IPBlock{ID: 1, ClientIP: addr, Reason: reason, Source: "automatic", FailureCount: failures, StrikeCount: r.automaticCalls, ExpiresAt: &expires, Active: true}
	return r.block, true, nil
}

// BlockManual 模拟永久封禁保存。
func (r *authAbuseTestRepository) BlockManual(_ context.Context, addr, reason string, seconds int, actor int64) (*IPBlock, error) {
	if r.mutationError != nil {
		return nil, r.mutationError
	}
	r.block = &IPBlock{ID: 1, ClientIP: addr, Reason: reason, Source: "manual", ActorUserID: &actor, Active: true}
	if seconds > 0 {
		expires := time.Now().Add(time.Duration(seconds) * time.Second)
		r.block.ExpiresAt = &expires
	}
	return r.block, nil
}

// Revoke 模拟解封但保留原记录。
func (r *authAbuseTestRepository) Revoke(_ context.Context, id int64) (*IPBlock, error) {
	now := time.Now()
	r.block.RevokedAt = &now
	r.block.Active = false
	return r.block, nil
}

// RecordAnomaly 模拟忽略时间边界和最近识别身份的保留，便于检查并发旧事件。
func (r *authAbuseTestRepository) RecordAnomaly(_ context.Context, item *AuthIPAnomaly) error {
	if r.mutationError != nil {
		return r.mutationError
	}
	if r.anomaly != nil && r.anomaly.DismissedAt != nil && !item.LastDetectedAt.After(*r.anomaly.DismissedAt) {
		return nil
	}
	r.anomalyCalls++
	copy := *item
	copy.ID = 1
	copy.FirstDetectedAt = item.LastDetectedAt
	if r.anomaly != nil {
		copy.FirstDetectedAt = r.anomaly.FirstDetectedAt
		if item.UserID == nil && item.APIKeyID == nil {
			copy.UserID = r.anomaly.UserID
			copy.APIKeyID = r.anomaly.APIKeyID
		}
	}
	r.anomaly = &copy
	return nil
}

// GetAnomaly 模拟查找异常摘要。
func (r *authAbuseTestRepository) GetAnomaly(_ context.Context, id int64) (*AuthIPAnomaly, error) {
	if r.anomaly != nil && r.anomaly.ID == id {
		return r.anomaly, nil
	}
	return nil, nil
}

// ListAnomalies 模拟不暴露凭证的分页结果。
func (r *authAbuseTestRepository) ListAnomalies(context.Context, AuthIPAnomalyFilter) ([]*AuthIPAnomaly, int64, error) {
	if r.anomaly == nil {
		return []*AuthIPAnomaly{}, 0, nil
	}
	return []*AuthIPAnomaly{r.anomaly}, 1, nil
}

// DismissAnomaly 模拟忽略提醒，保留历史摘要。
func (r *authAbuseTestRepository) DismissAnomaly(_ context.Context, id, actor int64) (*AuthIPAnomaly, error) {
	now := time.Now()
	r.anomaly.DismissedAt = &now
	return r.anomaly, nil
}

// newAuthAbuseTestService 创建隔离 Redis 和仓储，不连接业务数据库。
func newAuthAbuseTestService(t *testing.T) (*AuthAbuseService, *authAbuseTestRepository, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	repo := &authAbuseTestRepository{}
	cfg := &config.Config{Security: config.SecurityConfig{AuthAbuse: config.AuthAbuseConfig{
		Enabled: true, ShortWindowSeconds: 900, ShortThreshold: 10, LongWindowSeconds: 86400, LongThreshold: 30,
		InitialBlockSeconds: 1800, RepeatBlockSeconds: 86400,
	}}}
	return NewAuthAbuseService(repo, client, cfg), repo, server
}

// TestAuthAbuseLowFrequencyAndSharedInstances 覆盖每 218 秒一次的低频试错及跨实例累计。
func TestAuthAbuseLowFrequencyAndSharedInstances(t *testing.T) {
	svc, repo, server := newAuthAbuseTestService(t)
	other := NewAuthAbuseService(repo, svc.redis, &config.Config{Security: config.SecurityConfig{AuthAbuse: svc.cfg}})
	base := time.Now()
	for i := 0; i < 30; i++ {
		server.SetTime(base.Add(time.Duration(i) * 218 * time.Second))
		current := svc
		if i%2 == 1 {
			current = other
		}
		block, err := current.RecordFailure(context.Background(), "203.0.113.42", "invalid_credentials")
		require.NoError(t, err)
		if i < 29 {
			require.Nil(t, block)
		} else {
			require.NotNil(t, block)
			require.Equal(t, 30, block.FailureCount)
		}
	}
	require.Equal(t, 1, repo.automaticCalls)
	block, err := other.Check(context.Background(), "203.0.113.42")
	require.NoError(t, err)
	require.NotNil(t, block)
}

// TestAuthAbusePermanentPersistenceAndUnblock 覆盖缓存丢失后的恢复和解封清理旧计数。
func TestAuthAbusePermanentPersistenceAndUnblock(t *testing.T) {
	svc, repo, _ := newAuthAbuseTestService(t)
	ctx := context.Background()
	block, err := svc.BlockManual(ctx, "203.0.113.42", "manual review", 0, 7)
	require.NoError(t, err)
	require.Nil(t, block.ExpiresAt)
	cacheKey, failuresKey, sequenceKey, _ := authIPKeys(block.ClientIP)
	require.NoError(t, svc.redis.Del(ctx, cacheKey).Err())
	loaded, err := svc.Check(ctx, block.ClientIP)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	require.Greater(t, repo.reads, 0)
	require.NoError(t, svc.redis.ZAdd(ctx, failuresKey, redis.Z{Score: 1, Member: "old"}).Err())
	require.NoError(t, svc.redis.Set(ctx, sequenceKey, "1", time.Hour).Err())
	_, err = svc.Unblock(ctx, block.ID)
	require.NoError(t, err)
	exists, err := svc.redis.Exists(ctx, failuresKey, sequenceKey).Result()
	require.NoError(t, err)
	require.Zero(t, exists)
	loaded, err = svc.Check(ctx, block.ClientIP)
	require.NoError(t, err)
	require.Nil(t, loaded)
}

// TestAuthAbuseMutationAndDependencyFailure 确认并发变更及 Redis 故障均不会当作未封禁放行。
func TestAuthAbuseMutationAndDependencyFailure(t *testing.T) {
	svc, _, server := newAuthAbuseTestService(t)
	ctx := context.Background()
	_, _, _, lease := authIPKeys("203.0.113.42")
	require.NoError(t, svc.redis.Set(ctx, lease, "other-operation", time.Second).Err())
	_, err := svc.Check(ctx, "203.0.113.42")
	require.Error(t, err)
	_, err = svc.BlockManual(ctx, "203.0.113.42", "reason", 0, 7)
	require.Error(t, err)
	server.Close()
	_, err = svc.Check(ctx, "203.0.113.42")
	require.Error(t, err)
}

// TestAuthAbuseFailedMutationRetainsLease 确认保存失败后旧的空名单缓存不能绕过短租约。
func TestAuthAbuseFailedMutationRetainsLease(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		name := "manual"
		if automatic {
			name = "automatic"
		}
		t.Run(name, func(t *testing.T) {
			svc, repo, server := newAuthAbuseTestService(t)
			ctx := context.Background()
			addr := "203.0.113.42"
			_, err := svc.Check(ctx, addr)
			require.NoError(t, err)
			repo.mutationError = errors.New("storage unavailable")
			if automatic {
				svc.cfg.ShortThreshold = 3
				for i := 0; i < 2; i++ {
					_, err = svc.RecordFailure(ctx, addr, "invalid_credentials")
					require.NoError(t, err)
				}
				_, err = svc.RecordFailure(ctx, addr, "invalid_credentials")
			} else {
				_, err = svc.BlockManual(ctx, addr, "reason", 0, 7)
			}
			require.Error(t, err)
			_, err = svc.Check(ctx, addr)
			require.Equal(t, "IP_PROTECTION_BUSY", infraerrors.Reason(err))
			server.FastForward(ipBlockMutationLease)
			_, err = svc.Check(ctx, addr)
			require.NoError(t, err)
		})
	}
}

// TestAuthAbuseWhitelistAndNormalization 覆盖明确白名单及 IPv4/IPv6 规范化。
func TestAuthAbuseWhitelistAndNormalization(t *testing.T) {
	addr, err := NormalizeAuthIP("::ffff:203.0.113.42")
	require.NoError(t, err)
	require.Equal(t, "203.0.113.42", addr)
	for _, invalid := range []string{"unknown", "203.0.113.42:443", "203.0.113.0/24", "fe80::1%eth0"} {
		_, err := NormalizeAuthIP(invalid)
		require.Error(t, err)
	}
	svc, repo, _ := newAuthAbuseTestService(t)
	svc.whitelist = ip.CompileIPRules([]string{"203.0.113.0/24"})
	block, err := svc.Check(context.Background(), "203.0.113.42")
	require.NoError(t, err)
	require.Nil(t, block)
	require.Zero(t, repo.reads)
}

// TestAuthAbuseDetectionOnlyAndThrottle 确认自动封禁关闭时仍能检测且不会取得阻断租约。
func TestAuthAbuseDetectionOnlyAndThrottle(t *testing.T) {
	svc, repo, server := newAuthAbuseTestService(t)
	svc.cfg.Enabled = false
	svc.cfg.DetectionEnabled = true
	ctx := context.Background()
	addr := "203.0.113.42"
	base := time.Now()
	server.SetTime(base)
	meta := AuthFailureDetails{UserID: 7, APIKeyID: 8, PeerIP: "127.0.0.1", ClientIPSource: "remote_addr", Method: "POST", Route: "/v1/responses"}
	for i := 0; i < 10; i++ {
		block, err := svc.RecordFailure(ctx, addr, "api_key_disabled", meta)
		require.NoError(t, err)
		require.Nil(t, block)
		if i < 9 {
			require.Nil(t, repo.anomaly)
		}
	}
	require.Equal(t, 1, repo.anomalyCalls)
	require.Equal(t, 10, repo.anomaly.ShortFailures)
	require.Equal(t, int64(7), *repo.anomaly.UserID)
	require.Equal(t, int64(8), *repo.anomaly.APIKeyID)
	_, _, _, lease := authIPKeys(addr)
	exists, err := svc.redis.Exists(ctx, lease).Result()
	require.NoError(t, err)
	require.Zero(t, exists)
	block, err := svc.Check(ctx, addr)
	require.NoError(t, err)
	require.Nil(t, block)
	for i := 0; i < 10; i++ {
		_, err := svc.RecordFailure(ctx, addr, "api_key_disabled", meta)
		require.NoError(t, err)
	}
	require.Equal(t, 1, repo.anomalyCalls)
	server.FastForward(authAnomalyReportInterval)
	server.SetTime(base.Add(authAnomalyReportInterval))
	_, err = svc.RecordFailure(ctx, addr, "api_key_disabled", meta)
	require.NoError(t, err)
	require.Equal(t, 2, repo.anomalyCalls)
	require.Zero(t, repo.automaticCalls)
	require.Nil(t, repo.block)
}

// TestAuthAbuseDismissAndRedetect 确认忽略后需要新的失败达到阈值，旧检测不能恢复提醒。
func TestAuthAbuseDismissAndRedetect(t *testing.T) {
	svc, repo, server := newAuthAbuseTestService(t)
	svc.cfg.Enabled = false
	svc.cfg.DetectionEnabled = true
	ctx := context.Background()
	addr := "203.0.113.42"
	server.SetTime(time.Now())
	for i := 0; i < 10; i++ {
		_, err := svc.RecordFailure(ctx, addr, "invalid_credentials")
		require.NoError(t, err)
	}
	require.NotNil(t, repo.anomaly)
	require.Nil(t, repo.anomaly.UserID)
	require.Nil(t, repo.anomaly.APIKeyID)
	old := *repo.anomaly
	_, err := svc.DismissAnomaly(ctx, repo.anomaly.ID, 7)
	require.NoError(t, err)
	require.NotNil(t, repo.anomaly.DismissedAt)
	_, failures, sequence, _ := authIPKeys(addr)
	exists, err := svc.redis.Exists(ctx, failures, sequence, authAnomalyReportKey(addr)).Result()
	require.NoError(t, err)
	require.Zero(t, exists)
	require.NoError(t, repo.RecordAnomaly(ctx, &old))
	require.NotNil(t, repo.anomaly.DismissedAt)
	server.SetTime(time.Now().Add(time.Second))
	for i := 0; i < 9; i++ {
		_, err := svc.RecordFailure(ctx, addr, "invalid_credentials")
		require.NoError(t, err)
	}
	require.NotNil(t, repo.anomaly.DismissedAt)
	_, err = svc.RecordFailure(ctx, addr, "invalid_credentials")
	require.NoError(t, err)
	require.Nil(t, repo.anomaly.DismissedAt)
	require.Equal(t, 2, repo.anomalyCalls)
	require.Zero(t, repo.automaticCalls)
}
