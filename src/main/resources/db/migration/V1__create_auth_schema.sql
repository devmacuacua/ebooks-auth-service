-- Enable pgcrypto for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- users
-- ============================================================
CREATE TABLE users (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(255) UNIQUE NOT NULL,
    email_verified TIMESTAMP   NULL,
    password_hash VARCHAR(255) NULL,
    name          VARCHAR(255) NOT NULL,
    avatar        VARCHAR(512) NULL,
    phone         VARCHAR(50)  NULL,
    role          VARCHAR(20)  NOT NULL DEFAULT 'CUSTOMER'
                              CHECK (role IN ('CUSTOMER', 'ADMIN', 'EDITOR')),
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users (email);

-- ============================================================
-- oauth_accounts
-- ============================================================
CREATE TABLE oauth_accounts (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider            VARCHAR(20) NOT NULL CHECK (provider IN ('GOOGLE', 'FACEBOOK')),
    provider_account_id VARCHAR(255) NOT NULL,
    access_token        TEXT        NULL,
    refresh_token       TEXT        NULL,
    expires_at          BIGINT      NULL,
    UNIQUE (provider, provider_account_id)
);

CREATE INDEX idx_oauth_user_id ON oauth_accounts (user_id);

-- ============================================================
-- email_verifications
-- ============================================================
CREATE TABLE email_verifications (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token      VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP   NOT NULL,
    used       BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_ver_token ON email_verifications (token);

-- ============================================================
-- refresh_tokens
-- ============================================================
CREATE TABLE refresh_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token      VARCHAR(512) UNIQUE NOT NULL,
    expires_at TIMESTAMP   NOT NULL,
    revoked    BOOLEAN     NOT NULL DEFAULT FALSE,
    device_id  VARCHAR(255) NULL,
    created_at TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_user_id ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_token   ON refresh_tokens (token);

-- ============================================================
-- password_resets
-- ============================================================
CREATE TABLE password_resets (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token      VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP   NOT NULL,
    used       BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_pwd_reset_token ON password_resets (token);
