#!/bin/bash
# goauth E2E 测试服务器启动脚本
# 由 Playwright webServer 调用（工作目录：goauth/tests/e2e）
# 职责：
# 1. 清理旧数据库，保证干净的测试环境
# 2. 以测试环境配置启动 goauth 服务器
# 3. 等待服务器就绪后，用 CLI 创建固定管理员 e2e_admin
#    （否则第一个注册的用户会自动成为管理员，破坏"普通用户权限"等测试的前提）
set -e

cd "$(dirname "$0")/../.."

rm -rf data/goauth.db*

export APP_OIDC_ISSUER="${APP_OIDC_ISSUER:-http://localhost:3000}"
export APP_SECURITY_LOGINMAXATTEMPTS=1000
export APP_SERVER_RATELIMIT=0
export APP_SECURITY_AUTOAPPROVEUSERS=true

./bin/goauth serve &
SERVER_PID=$!

# 等待服务器就绪（最多 30 秒）
for i in $(seq 1 30); do
  if curl -sf http://localhost:3000/health >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# 创建固定管理员（密码与 tests/e2e/fixture.ts 中 STRONG_PASSWORD 一致）
./bin/goauth create-admin -u e2e_admin -p 'Correct-Horse-Battery-Staple-2024!' || true

wait $SERVER_PID
