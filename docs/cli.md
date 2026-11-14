# CLI 命令

CLI 命令可以通过运行 Goauth 并传递参数来访问。一种方法是使用现有的应用 compose 文件，在 `compose.yaml` 所在目录下以 `docker compose run goauth <command> [options]` 格式运行命令。

## 启动服务

```bash
goauth serve [--config config.yaml]
```

这是默认命令（如果未指定其他命令），用于启动 Goauth 应用。

## 数据库迁移

```bash
goauth migrate [--config config.yaml]
```

运行数据库迁移。

## 重置密码

```bash
goauth reset-password -u <username>
```

重置现有用户的密码。新密码将输出到控制台。

## 创建管理员

```bash
goauth create-admin -u <username> -p <password>
```

创建一个新的管理员用户，使用指定的用户名和密码。该用户将拥有管理员权限（`isAdmin` 标识），可访问管理后台的全部功能。

## 查看版本

```bash
goauth --version
```

显示 Goauth 的当前版本。