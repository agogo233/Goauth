package oidc

import (
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/op"

	"goauth/internal/config"
)

// Provider OIDC Provider 封装
type Provider struct {
	provider *op.Provider
	storage  *Storage
	config   *config.Config
}

// NewProvider 创建 OIDC Provider
func NewProvider(cfg *config.Config, storage *Storage) (*Provider, error) {
	// 创建 provider 配置
	opConfig := &op.Config{
		DefaultLogoutRedirectURI: "/",
	}

	// 转换加密密钥
	var cryptoKey [32]byte
	copy(cryptoKey[:], cfg.Security.CryptoKey)
	opConfig.CryptoKey = cryptoKey

	// Provider 选项
	var opts []op.Option

	// 开发/测试模式允许 HTTP
	if cfg.Server.Environment == "development" || cfg.Server.Environment == "test" {
		opts = append(opts, op.WithAllowInsecure())
	}

	// 创建 provider
	provider, err := op.NewProvider(opConfig, storage, op.StaticIssuer(cfg.OIDC.Issuer), opts...)
	if err != nil {
		return nil, err
	}

	return &Provider{
		provider: provider,
		storage:  storage,
		config:   cfg,
	}, nil
}

// Handler 返回 OIDC HTTP Handler
func (p *Provider) Handler() http.Handler {
	return p.provider.HttpHandler()
}

// Storage 返回 Storage
func (p *Provider) Storage() *Storage {
	return p.storage
}

// OpProvider 返回底层 op.Provider
func (p *Provider) OpProvider() *op.Provider {
	return p.provider
}


