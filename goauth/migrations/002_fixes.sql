-- Goauth 数据库迁移 v0.0.2
-- 修复：TOTP 备用码、Session 滑动过期优化、审计日志 IP 索引

-- 1. 添加 lastRefreshedAt 字段到 sessions 表
ALTER TABLE sessions ADD COLUMN lastRefreshedAt TEXT;

-- 1b. 确保 totpAttempts 列存在（旧版本数据库升级）
ALTER TABLE sessions ADD COLUMN totpAttempts INTEGER DEFAULT 0;

-- 2. 创建 TOTP 备用码表
CREATE TABLE IF NOT EXISTS totp_backup_codes (
    userId TEXT PRIMARY KEY NOT NULL,
    codesHash TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
);

-- 3. 审计日志 IP 索引（加速按 IP 查询）
CREATE INDEX IF NOT EXISTS idx_audit_log_ip ON audit_log(ip);

-- 4. 登录尝试记录复合索引（加速暴力破解防护的计数查询）
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_success_created ON login_attempts(ip, success, createdAt);