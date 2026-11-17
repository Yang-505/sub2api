-- 持续认证失败与手动 IP 封禁的独立名单，不改动已有用户和业务数据。
CREATE TABLE IF NOT EXISTS auth_ip_blocks (
    id BIGSERIAL PRIMARY KEY,
    client_ip INET NOT NULL UNIQUE,
    reason VARCHAR(128) NOT NULL,
    source VARCHAR(16) NOT NULL CHECK (source IN ('automatic', 'manual')),
    failure_count INTEGER NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    strike_count INTEGER NOT NULL DEFAULT 0 CHECK (strike_count >= 0),
    actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_auth_ip_blocks_updated ON auth_ip_blocks (updated_at DESC, id DESC);
