# 备份与恢复

Goauth 的所有状态都保存在数据目录（默认 `./data/`，Docker 中为 `/app/data`）中。做好该目录的备份，即可在故障或迁移时完整恢复。

## 数据目录内容

| 文件 | 说明 |
|------|------|
| `goauth.db` | SQLite 数据库（WAL 模式），包含用户、会话、OIDC 客户端、审计日志等全部数据 |
| `goauth.db-wal` / `goauth.db-shm` | SQLite WAL 日志与共享内存文件，属于数据库的一部分 |
| `.goauth-keys` | 自动生成的密钥文件，包含 `cryptoKey`（AES-256-GCM 密钥）和 `cookieKeys`（会话签名密钥） |

> [!CAUTION]
> `.goauth-keys` **不可丢失**。OIDC Token 与 RSA 私钥等敏感数据使用 `cryptoKey` 加密存储，密钥丢失后这些数据将**无法解密**，只能清库重建。

## 备份

### 方式一：停机备份（推荐）

停止 Goauth 后直接复制整个数据目录：

```bash
docker compose stop goauth
tar czf goauth-backup-$(date +%F).tar.gz data/
docker compose start goauth
```

### 方式二：在线备份

运行中使用 SQLite 的备份接口，避免复制到写入中途的 WAL 状态：

```bash
sqlite3 data/goauth.db "VACUUM INTO 'goauth-backup.db'"
```

> [!NOTE]
> `VACUUM INTO` 只备份数据库主体，不含 `.goauth-keys`。密钥文件需单独复制。

### Docker 部署

数据保存在 named volume（如 `goauth-data`）中。可以临时启动一个容器打包：

```bash
docker run --rm -v goauth-data:/data -v $PWD:/backup alpine \
  tar czf /backup/goauth-data-$(date +%F).tar.gz -C /data .
```

## 恢复

1. 停止 Goauth。
2. 清空或移走现有数据目录，将备份的 `goauth.db`（以及 WAL/SHM 文件，如有）和 `.goauth-keys` 放回数据目录。
3. 确保文件属主与权限正确（`.goauth-keys` 建议保持 `0600`）。
4. 重新启动 Goauth。启动时会自动运行数据库迁移，将 schema 升级到当前版本。

## 迁移到新服务器

1. 在旧服务器停止 Goauth，打包整个 `data/` 目录（数据库 + `.goauth-keys`）。
2. 在新服务器解压到相同的数据目录位置。
3. 启动 Goauth 并执行 `goauth migrate`（`serve` 启动时也会自动迁移）。

> [!TIP]
> 也可以通过环境变量 `APP_SECURITY_CRYPTOKEY`（32 字节 base64）预置加密密钥，使数据库与密钥分离备份成为可能。但请妥善保管该变量，不要提交到版本库。
