package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

const anomalyActiveBlock = `(b.revoked_at IS NULL AND (b.expires_at IS NULL OR b.expires_at > NOW()))`
const anomalyJoins = ` FROM auth_ip_anomalies a LEFT JOIN users u ON u.id=a.user_id
LEFT JOIN auth_ip_blocks b ON b.client_ip=a.client_ip`
const anomalyColumns = `a.id, host(a.client_ip), a.reason, a.short_failures, a.long_failures,
a.short_window_seconds, a.long_window_seconds, a.user_id, COALESCE(u.email,''), a.api_key_id,
COALESCE(host(a.peer_ip),''), a.client_ip_source, a.method, a.route,
a.first_detected_at, a.last_detected_at, a.dismissed_at,
CASE WHEN b.id IS NOT NULL AND ` + anomalyActiveBlock + ` THEN b.id ELSE NULL END,
(b.id IS NOT NULL AND ` + anomalyActiveBlock + `)`

// scanAuthIPAnomaly 将摘要与当前封禁状态映射到管理员列表，不返回任何 Key 字符串。
func scanAuthIPAnomaly(row interface{ Scan(...any) error }) (*service.AuthIPAnomaly, error) {
	item := &service.AuthIPAnomaly{}
	err := row.Scan(&item.ID, &item.ClientIP, &item.Reason, &item.ShortFailures, &item.LongFailures,
		&item.ShortWindowSeconds, &item.LongWindowSeconds, &item.UserID, &item.UserEmail, &item.APIKeyID,
		&item.PeerIP, &item.ClientIPSource, &item.Method, &item.Route, &item.FirstDetectedAt, &item.LastDetectedAt,
		&item.DismissedAt, &item.BlockID, &item.Blocked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return item, nil
}

// RecordAnomaly 更新限频检测摘要；忽略前已发生的并发事件不能重新激活提醒。
func (r *ipBlockRepository) RecordAnomaly(ctx context.Context, item *service.AuthIPAnomaly) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO auth_ip_anomalies
(client_ip,reason,short_failures,long_failures,short_window_seconds,long_window_seconds,user_id,api_key_id,
peer_ip,client_ip_source,method,route,first_detected_at,last_detected_at)
VALUES ($1::inet,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,'')::inet,$10,$11,$12,$13,$13)
ON CONFLICT (client_ip) DO UPDATE SET reason=EXCLUDED.reason,short_failures=EXCLUDED.short_failures,
long_failures=EXCLUDED.long_failures,short_window_seconds=EXCLUDED.short_window_seconds,
long_window_seconds=EXCLUDED.long_window_seconds,
user_id=CASE WHEN EXCLUDED.user_id IS NOT NULL OR EXCLUDED.api_key_id IS NOT NULL THEN EXCLUDED.user_id ELSE auth_ip_anomalies.user_id END,
api_key_id=CASE WHEN EXCLUDED.user_id IS NOT NULL OR EXCLUDED.api_key_id IS NOT NULL THEN EXCLUDED.api_key_id ELSE auth_ip_anomalies.api_key_id END,
peer_ip=EXCLUDED.peer_ip,client_ip_source=EXCLUDED.client_ip_source,method=EXCLUDED.method,route=EXCLUDED.route,
last_detected_at=EXCLUDED.last_detected_at,dismissed_at=NULL,dismissed_by=NULL
WHERE EXCLUDED.last_detected_at >= auth_ip_anomalies.last_detected_at
AND (auth_ip_anomalies.dismissed_at IS NULL OR EXCLUDED.last_detected_at > auth_ip_anomalies.dismissed_at)`,
		item.ClientIP, item.Reason, item.ShortFailures, item.LongFailures, item.ShortWindowSeconds, item.LongWindowSeconds,
		item.UserID, item.APIKeyID, item.PeerIP, item.ClientIPSource, item.Method, item.Route, item.LastDetectedAt)
	return err
}

// GetAnomaly 读取待处理条目；不存在时返回 nil，供服务层转换为 404。
func (r *ipBlockRepository) GetAnomaly(ctx context.Context, id int64) (*service.AuthIPAnomaly, error) {
	return scanAuthIPAnomaly(r.db.QueryRowContext(ctx, `SELECT `+anomalyColumns+anomalyJoins+` WHERE a.id=$1`, id))
}

// ListAnomalies 按真实 IP、已识别用户和当前处理状态读取摘要。
func (r *ipBlockRepository) ListAnomalies(ctx context.Context, filter service.AuthIPAnomalyFilter) ([]*service.AuthIPAnomaly, int64, error) {
	where := ` WHERE ($1='' OR a.client_ip=NULLIF($1,'')::inet) AND ($2::bigint=0 OR a.user_id=$2::bigint)
AND ($3='all' OR ($3='blocked' AND b.id IS NOT NULL AND ` + anomalyActiveBlock + `)
OR ($3='dismissed' AND a.dismissed_at IS NOT NULL AND NOT COALESCE(b.id IS NOT NULL AND ` + anomalyActiveBlock + `,false))
OR ($3='pending' AND a.dismissed_at IS NULL AND NOT COALESCE(b.id IS NOT NULL AND ` + anomalyActiveBlock + `,false)))`
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*)`+anomalyJoins+where, filter.ClientIP, filter.UserID, filter.Status).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+anomalyColumns+anomalyJoins+where+` ORDER BY a.last_detected_at DESC,a.id DESC LIMIT $4 OFFSET $5`,
		filter.ClientIP, filter.UserID, filter.Status, filter.Size, (filter.Page-1)*filter.Size)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]*service.AuthIPAnomaly, 0)
	for rows.Next() {
		item, err := scanAuthIPAnomaly(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

// DismissAnomaly 标记人工忽略并保留摘要，管理员操作由入口审计记录。
func (r *ipBlockRepository) DismissAnomaly(ctx context.Context, id, actor int64) (*service.AuthIPAnomaly, error) {
	result, err := r.db.ExecContext(ctx, `UPDATE auth_ip_anomalies SET dismissed_at=NOW(),dismissed_by=$2 WHERE id=$1`, id, actor)
	if err != nil {
		return nil, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, fmt.Errorf("IP anomaly %d does not exist", id)
	}
	return r.GetAnomaly(ctx, id)
}
