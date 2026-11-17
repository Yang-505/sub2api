package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

type ipBlockRepository struct{ db *sql.DB }

const ipBlockColumns = `id, host(client_ip), reason, source, failure_count, strike_count,
actor_user_id, expires_at, revoked_at, created_at, updated_at,
(revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()))`

// NewIPBlockRepository 创建独立封禁名单仓储，复用现有数据库连接。
func NewIPBlockRepository(db *sql.DB) service.IPBlockRepository { return &ipBlockRepository{db: db} }

// scanIPBlock 将查询结果映射为封禁记录，不存在时返回 nil。
func scanIPBlock(row interface{ Scan(...any) error }) (*service.IPBlock, error) {
	b := &service.IPBlock{}
	err := row.Scan(&b.ID, &b.ClientIP, &b.Reason, &b.Source, &b.FailureCount, &b.StrikeCount,
		&b.ActorUserID, &b.ExpiresAt, &b.RevokedAt, &b.CreatedAt, &b.UpdatedAt, &b.Active)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Find 按规范化 IP 读取历史或当前封禁。
func (r *ipBlockRepository) Find(ctx context.Context, addr string) (*service.IPBlock, error) {
	return scanIPBlock(r.db.QueryRowContext(ctx, `SELECT `+ipBlockColumns+` FROM auth_ip_blocks WHERE client_ip=$1::inet`, addr))
}

// Get 按记录 ID 读取名单，供解封操作使用。
func (r *ipBlockRepository) Get(ctx context.Context, id int64) (*service.IPBlock, error) {
	return scanIPBlock(r.db.QueryRowContext(ctx, `SELECT `+ipBlockColumns+` FROM auth_ip_blocks WHERE id=$1`, id))
}

// List 分页读取有效名单或封禁历史。
func (r *ipBlockRepository) List(ctx context.Context, page, size int, activeOnly bool) ([]*service.IPBlock, int64, error) {
	where := ` WHERE (NOT $1 OR (revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())))`
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_ip_blocks`+where, activeOnly).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+ipBlockColumns+` FROM auth_ip_blocks`+where+` ORDER BY updated_at DESC, id DESC LIMIT $2 OFFSET $3`, activeOnly, size, (page-1)*size)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]*service.IPBlock, 0)
	for rows.Next() {
		item, err := scanIPBlock(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

// BlockAutomatic 在到期或已解封后原子升级处罚；并发触发不会重复增加次数或覆盖永久封禁。
func (r *ipBlockRepository) BlockAutomatic(ctx context.Context, addr, reason string, failures int, cfg config.AuthAbuseConfig) (*service.IPBlock, bool, error) {
	query := `INSERT INTO auth_ip_blocks (client_ip,reason,source,failure_count,strike_count,expires_at)
VALUES ($1::inet,$2,'automatic',$3,1,NOW()+$4*INTERVAL '1 second')
ON CONFLICT (client_ip) DO UPDATE SET reason=$2, source='automatic', failure_count=$3,
strike_count=auth_ip_blocks.strike_count+1, actor_user_id=NULL, revoked_at=NULL, updated_at=NOW(),
expires_at=CASE WHEN $6>0 AND auth_ip_blocks.strike_count+1 >= $6 THEN NULL
ELSE NOW()+(CASE WHEN auth_ip_blocks.strike_count=0 THEN $4 ELSE $5 END)*INTERVAL '1 second' END
WHERE auth_ip_blocks.revoked_at IS NOT NULL OR auth_ip_blocks.expires_at <= NOW()
RETURNING ` + ipBlockColumns
	b, err := scanIPBlock(r.db.QueryRowContext(ctx, query, addr, reason, failures, cfg.InitialBlockSeconds, cfg.RepeatBlockSeconds, cfg.PermanentAfter))
	if err != nil {
		return nil, false, err
	}
	if b == nil {
		b, err = r.Find(ctx, addr)
		return b, false, err
	}
	return b, true, nil
}

// BlockManual 设置管理员指定的临时或永久封禁，保留原有自动处罚历史。
func (r *ipBlockRepository) BlockManual(ctx context.Context, addr, reason string, seconds int, actor int64) (*service.IPBlock, error) {
	query := `INSERT INTO auth_ip_blocks (client_ip,reason,source,actor_user_id,expires_at)
VALUES ($1::inet,$2,'manual',$3,CASE WHEN $4=0 THEN NULL ELSE NOW()+$4*INTERVAL '1 second' END)
ON CONFLICT (client_ip) DO UPDATE SET reason=$2,source='manual',actor_user_id=$3,revoked_at=NULL,
expires_at=CASE WHEN $4=0 THEN NULL ELSE NOW()+$4*INTERVAL '1 second' END,updated_at=NOW()
RETURNING ` + ipBlockColumns
	return scanIPBlock(r.db.QueryRowContext(ctx, query, addr, reason, actor, seconds))
}

// Revoke 解除封禁但保留历史记录，重复解封保持幂等。
func (r *ipBlockRepository) Revoke(ctx context.Context, id int64) (*service.IPBlock, error) {
	b, err := scanIPBlock(r.db.QueryRowContext(ctx, `UPDATE auth_ip_blocks SET revoked_at=NOW(),updated_at=NOW() WHERE id=$1 RETURNING `+ipBlockColumns, id))
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("IP block %d does not exist", id)
	}
	return b, nil
}
