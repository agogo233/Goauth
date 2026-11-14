package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/rs/zerolog/log"
)

const keyFileName = ".goauth-keys"

type keyFile struct {
	CryptoKey  string   `json:"cryptoKey"`
	CookieKeys []string `json:"cookieKeys"`
}

type Config struct {
	Server   ServerConfig   `koanf:"server"`
	Database DatabaseConfig `koanf:"database"`
	OIDC     OIDCConfig     `koanf:"oidc"`
	Session  SessionConfig  `koanf:"session"`
	Security SecurityConfig `koanf:"security"`
	UI       UIConfig       `koanf:"ui"`
	Logging  LoggingConfig  `koanf:"logging"`
}

type SessionConfig struct {
	TTL         time.Duration `koanf:"ttl"`         // 普通登录 Session TTL
	TTLRemember time.Duration `koanf:"ttlremember"` // "记住我" Session TTL
}

type ServerConfig struct {
	Port             int      `koanf:"port"`
	Host             string   `koanf:"host"`
	Environment      string   `koanf:"environment"`
	AppURL           string   `koanf:"appurl"`
	BasePath         string   `koanf:"basepath"`
	Timezone         string   `koanf:"timezone"`
	CookieDomain     string   `koanf:"cookiedomain"`
	CookieSecure     string   `koanf:"cookiesecure"`     // "auto", "true", "false"
	CookieSameSite   string   `koanf:"cookiesamesite"`   // "strict", "lax", "none"
	CORSAllowOrigins []string `koanf:"corsalloworigins"` // CORS 允许的来源列表
}

type DatabaseConfig struct {
	Path string `koanf:"path"`
}

type OIDCConfig struct {
	Issuer          string        `koanf:"issuer"`
	CookieKeys      []string      `koanf:"cookiekeys"`
	AccessTokenTTL  time.Duration `koanf:"accesstokenttl"`
	IDTokenTTL      time.Duration `koanf:"idtokenttl"`
	RefreshTokenTTL time.Duration `koanf:"refreshtokenttl"`
	SessionTTL      time.Duration `koanf:"sessionttl"`
	InteractionTTL  time.Duration `koanf:"interactionttl"`
	GrantTTL        time.Duration `koanf:"grantttl"`
	ConsentTTL      time.Duration `koanf:"consentttl"`
}

type SecurityConfig struct {
	CryptoKey           []byte `koanf:"cryptokey"`
	PasswordMin         int    `koanf:"passwordmin"`
	PasswordMinScore    int    `koanf:"passwordminscore"`
	BcryptCost          int    `koanf:"bcryptcost"` // bcrypt 哈希成本（4-31），默认 12
	LoginMaxAttempts    int    `koanf:"loginmaxattempts"`
	LoginBlockDuration  int    `koanf:"loginblockduration"`
	TotpMaxAttempts     int    `koanf:"totpmaxattempts"`     // TOTP 最大尝试次数
	AuditLogRetention   int    `koanf:"auditlogretention"`   // 审计日志保留天数
	LoginAttemptCleanup int    `koanf:"loginattemptcleanup"` // 登录尝试记录清理间隔（小时）
	AutoApproveUsers    bool   `koanf:"autoapproveusers"`    // 自动批准所有注册用户（用于测试环境）
}

type UIConfig struct {
	AppName       string `koanf:"appname"`
	AppColor      string `koanf:"appcolor"`
	SignupEnabled bool   `koanf:"signupenabled"`
}

type LoggingConfig struct {
	Level string `koanf:"level"`
}

func Load(configPath string) (*Config, error) {
	k := koanf.New(".")

	// Load .env file if exists
	loadEnvFile(".env")

	// Load config file if provided
	if configPath != "" {
		if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
			log.Warn().Err(err).Msg("Failed to load config file")
		}
	}

	// Load environment variables with APP_ prefix
	k.Load(env.Provider("APP_", ".", func(s string) string {
		// 支持两种环境变量风格：
		//   APP_SERVER_PORT   -> server.port（推荐，单一 "_" 分隔）
		//   APP_SERVER_PORT_X -> 兼容旧的 "APP_A_B" -> "a.b" 映射
		name := strings.ToLower(strings.TrimPrefix(s, "APP_"))
		// 常见配置键显式映射，避免 "SERVER_PORT" 被误解析为 "server.port.x"
		known := map[string]string{
			"server_port":               "server.port",
			"server_host":               "server.host",
			"server_environment":        "server.environment",
			"server_appurl":             "server.appurl",
			"server_basepath":           "server.basepath",
			"server_timezone":           "server.timezone",
			"server_ratelimit":          "server.ratelimit",
			"server_cookieDomain":       "server.cookiedomain",
			"database_path":             "database.path",
			"security_cryptokey":        "security.cryptokey",
			"security_bcryptcost":       "security.bcryptcost",
			"security_autoapproveusers": "security.autoapproveusers",
			"oidc_issuer":               "oidc.issuer",
			"ui_appname":                "ui.appname",
			"logging_level":             "logging.level",
		}
		if v, ok := known[name]; ok {
			return v
		}
		return strings.Replace(name, "_", ".", -1)
	}), nil)

	// Build config with defaults
	// 注意：defaults 直接写入 cfg，再由 k.Unmarshal 用已加载的 env/file 值覆盖
	cfg := &Config{
		Server: ServerConfig{
			Port:             3000,
			Host:             "0.0.0.0",
			Environment:      "development",
			AppURL:           "",
			BasePath:         "",
			Timezone:         "UTC",
			CookieDomain:     "",
			CookieSecure:     "auto",
			CookieSameSite:   "lax",
			CORSAllowOrigins: []string{}, // 默认空，仅允许同源请求
		},
		Database: DatabaseConfig{
			Path: "./data/goauth.db",
		},
		OIDC: OIDCConfig{
			AccessTokenTTL:  15 * time.Minute,
			IDTokenTTL:      30 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
			SessionTTL:      30 * 24 * time.Hour, // OIDC 会话 30 天（从 90 天缩短，降低 token 泄露风险）
			InteractionTTL:  10 * time.Minute,
			GrantTTL:        30 * 24 * time.Hour,
			ConsentTTL:      30 * 24 * time.Hour,
		},
		Session: SessionConfig{
			TTL:         24 * time.Hour,      // 普通登录 24 小时
			TTLRemember: 30 * 24 * time.Hour, // "记住我" 30 天
		},
		Security: SecurityConfig{
			PasswordMin:         8,
			PasswordMinScore:    3,
			BcryptCost:          12, // 默认 12，可通过 APP_SECURITY_BCRYPTCOST 配置
			LoginMaxAttempts:    10,
			LoginBlockDuration:  30,
			TotpMaxAttempts:     5,
			AuditLogRetention:   90,    // 默认保留 90 天
			LoginAttemptCleanup: 24,    // 默认每 24 小时清理一次
			AutoApproveUsers:    false, // 默认不自动批准
		},
		UI: UIConfig{
			AppName:       "Goauth",
			AppColor:      "#906bc7",
			SignupEnabled: true,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}

	// Unmarshal into config struct
	if err := k.Unmarshal("", cfg); err != nil {
		return nil, err
	}

	// 显式环境变量覆盖（koanf env.Provider 对部分键的映射可能与结构体 tag 不一致，
	// 这里对关键配置做最终覆盖，确保 APP_* 环境变量优先于默认值）
	if v := os.Getenv("APP_SERVER_PORT"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			cfg.Server.Port = n
		}
	}
	if v := os.Getenv("APP_SERVER_HOST"); v != "" {
		cfg.Server.Host = strings.TrimSpace(v)
	}
	if v := os.Getenv("APP_SERVER_ENVIRONMENT"); v != "" {
		cfg.Server.Environment = strings.TrimSpace(v)
	}
	if v := os.Getenv("APP_SERVER_APPURL"); v != "" {
		cfg.Server.AppURL = strings.TrimSpace(v)
	}
	if v := os.Getenv("APP_SERVER_BASEPATH"); v != "" {
		cfg.Server.BasePath = strings.TrimSpace(v)
	}
	if v := os.Getenv("APP_SERVER_TIMEZONE"); v != "" {
		cfg.Server.Timezone = strings.TrimSpace(v)
	}
	if v := os.Getenv("APP_DATABASE_PATH"); v != "" {
		cfg.Database.Path = strings.TrimSpace(v)
	}
	if v := os.Getenv("APP_OIDC_ISSUER"); v != "" {
		cfg.OIDC.Issuer = strings.TrimSpace(v)
	}
	if v := os.Getenv("APP_SECURITY_AUTOAPPROVEUSERS"); v != "" {
		cfg.Security.AutoApproveUsers = strings.EqualFold(strings.TrimSpace(v), "true")
	}
	if v := os.Getenv("APP_UI_APPNAME"); v != "" {
		cfg.UI.AppName = strings.TrimSpace(v)
	}
	if v := os.Getenv("APP_LOGGING_LEVEL"); v != "" {
		cfg.Logging.Level = strings.TrimSpace(v)
	}

	// Set issuer to AppURL if not specified
	if cfg.OIDC.Issuer == "" {
		cfg.OIDC.Issuer = cfg.Server.AppURL
	}

	// Load or generate keys (with persistence)
	dbPath := filepath.Dir(cfg.Database.Path)
	if err := loadOrGenerateKeys(cfg, dbPath); err != nil {
		return nil, err
	}

	return cfg, nil
}

// loadOrGenerateKeys 从文件加载密钥，不存在则生成并保存
func loadOrGenerateKeys(cfg *Config, dbPath string) error {
	keyPath := filepath.Join(dbPath, keyFileName)

	// 如果配置中已提供密钥，直接使用
	if len(cfg.OIDC.CookieKeys) > 0 && len(cfg.Security.CryptoKey) > 0 {
		return nil
	}

	// 尝试从文件加载
	data, err := os.ReadFile(keyPath)
	if err == nil {
		var kf keyFile
		if err := json.Unmarshal(data, &kf); err == nil {
			if len(cfg.OIDC.CookieKeys) == 0 && len(kf.CookieKeys) > 0 {
				cfg.OIDC.CookieKeys = kf.CookieKeys
				log.Info().Msg("Loaded cookie keys from file")
			}
			if len(cfg.Security.CryptoKey) == 0 && kf.CryptoKey != "" {
				// 解码 base64 得到原始 32 字节
				decoded, err := base64.StdEncoding.DecodeString(kf.CryptoKey)
				if err == nil && len(decoded) == 32 {
					cfg.Security.CryptoKey = decoded
					log.Info().Msg("Loaded crypto key from file")
				} else {
					log.Warn().Err(err).Msg("Failed to decode crypto key, generating new one")
				}
			}
			return nil
		}
		log.Warn().Err(err).Msg("Failed to parse key file, generating new keys")
	}

	// 生成新密钥
	needsSave := false

	if len(cfg.OIDC.CookieKeys) == 0 {
		key := generateKey(32)
		cfg.OIDC.CookieKeys = []string{key}
		log.Info().Msg("Generated new cookie key")
		needsSave = true
	}

	if len(cfg.Security.CryptoKey) == 0 {
		// 生成原始 32 字节密钥
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Fatal().Err(err).Msg("Failed to generate crypto key")
		}
		cfg.Security.CryptoKey = key
		log.Info().Msg("Generated new crypto key")
		needsSave = true
	}

	// 保存到文件
	if needsSave {
		if err := saveKeys(keyPath, cfg); err != nil {
			log.Warn().Err(err).Msg("Failed to save keys file")
		} else {
			log.Info().Str("path", keyPath).Msg("Saved keys to file")
		}
	}

	return nil
}

// saveKeys 保存密钥到文件
func saveKeys(keyPath string, cfg *Config) error {
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return err
	}

	kf := keyFile{
		CryptoKey:  base64.StdEncoding.EncodeToString(cfg.Security.CryptoKey),
		CookieKeys: cfg.OIDC.CookieKeys,
	}

	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}

	// 写入文件，权限仅限所有者
	return os.WriteFile(keyPath, data, 0600)
}

func generateKey(length int) string {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		log.Fatal().Err(err).Msg("Failed to generate key")
	}
	return base64.StdEncoding.EncodeToString(key)
}

// IsCookieSecure 判断是否应该使用 Secure cookie
// auto: 根据 AppURL 是否为 https 自动判断
// true: 强制启用
// false: 强制禁用
func (c *Config) IsCookieSecure() bool {
	switch c.Server.CookieSecure {
	case "true":
		return true
	case "false":
		return false
	default: // auto
		return strings.HasPrefix(c.Server.AppURL, "https://")
	}
}

// GetCookieSameSite 解析 SameSite 配置
// strict: 完全禁止第三方 cookie（最安全，可能影响某些场景）
// lax: 允许安全的第三方请求携带 cookie（推荐，默认）
// none: 允许所有第三方请求携带 cookie（需要 Secure=true）
func (c *Config) GetCookieSameSite() string {
	sameSite := strings.ToLower(c.Server.CookieSameSite)
	switch sameSite {
	case "strict", "none":
		return sameSite
	default:
		return "lax"
	}
}

// loadEnvFile 从文件加载环境变量（替代 godotenv）
func loadEnvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return // 文件不存在不报错
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// 真实环境变量优先于 .env 文件（不要覆盖已存在的进程环境变量）
			if _, exists := os.LookupEnv(key); exists {
				continue
			}
			// 移除引号
			if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[0] == value[len(value)-1] {
				value = value[1 : len(value)-1]
			}
			os.Setenv(key, value)
		}
	}
}
