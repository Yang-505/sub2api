-- 认证试错的检测摘要，独立于用户和 IP 封禁数据；每个 IP 只保存一条摘要。
CREATE TABLE IF NOT EXISTS auth_ip_anomalies (
    id BIGSERIAL PRIMARY KEY,
    client_ip INET NOT NULL UNIQUE,
    reason VARCHAR(128) NOT NULL,
    short_failures INTEGER NOT NULL CHECK (short_failures >= 0),
    long_failures INTEGER NOT NULL CHECK (long_failures >= 0),
    short_window_seconds INTEGER NOT NULL,
    long_window_seconds INTEGER NOT NULL,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    api_key_id BIGINT REFERENCES api_keys(id) ON DELETE SET NULL,
    peer_ip INET,
    client_ip_source VARCHAR(128) NOT NULL DEFAULT '',
    method VARCHAR(16) NOT NULL DEFAULT '',
    route VARCHAR(512) NOT NULL DEFAULT '',
    first_detected_at TIMESTAMPTZ NOT NULL,
    last_detected_at TIMESTAMPTZ NOT NULL,
    dismissed_at TIMESTAMPTZ,
    dismissed_by BIGINT REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_ip_anomalies_recent ON auth_ip_anomalies (last_detected_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_auth_ip_anomalies_user ON auth_ip_anomalies (user_id, last_detected_at DESC);
