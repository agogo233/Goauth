package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog/log"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/crypto/bcrypt"

	"goauth/internal/config"
	"goauth/internal/model"
	"goauth/internal/repo"
)

var (
	ErrInvalidClient    = errors.New("invalid client")
	ErrInvalidGrant     = errors.New("invalid grant")
	ErrInvalidRequest   = errors.New("invalid request")
	ErrUnauthorizedUser = errors.New("unauthorized user")
)

// Storage 实现 op.Storage 接口
type Storage struct {
	oidcRepo    *repo.OIDCRepo
	userRepo    *repo.UserRepo
	groupRepo   *repo.GroupRepo
	keyRepo     *repo.KeyRepo
	clientRepo  *repo.ClientRepo // 添加 clientRepo 以从 clients 表读取
	sessionRepo *repo.SessionRepo // 添加 sessionRepo 用于 SSO 登出
	cfg         *config.Config
	key         *rsa.PrivateKey
	keyOnce     sync.Once  // 确保 initSigningKey 只执行一次
	keyInitErr  error      // 存储初始化错误
}

// NewStorage 创建 Storage
func NewStorage(userRepo *repo.UserRepo, groupRepo *repo.GroupRepo, keyRepo *repo.KeyRepo, oidcRepo *repo.OIDCRepo, clientRepo *repo.ClientRepo, sessionRepo *repo.SessionRepo, cfg *config.Config) (*Storage, error) {
	s := &Storage{
		oidcRepo:    oidcRepo,
		userRepo:    userRepo,
		groupRepo:   groupRepo,
		keyRepo:     keyRepo,
		clientRepo:  clientRepo,
		sessionRepo: sessionRepo,
		cfg:         cfg,
	}

	// 初始化签名密钥（使用 sync.Once 保护）
	s.keyOnce.Do(func() {
		s.keyInitErr = s.doInitSigningKey(context.Background())
	})

	if s.keyInitErr != nil {
		return nil, s.keyInitErr
	}

	return s, nil
}

// doInitSigningKey 初始化签名密钥（内部方法，由 sync.Once 保护调用）
func (s *Storage) doInitSigningKey(ctx context.Context) error {
	// 尝试从数据库加载现有密钥
	existingKeys, err := s.keyRepo.FindValidByType(ctx, "oidc_signing_key")
	if err == nil && len(existingKeys) > 0 {
		latestKey := existingKeys[0]
		key, err := parseRSAKey(latestKey.Value)
		if err == nil {
			s.key = key
			return nil
		}
		log.Warn().Err(err).Msg("Failed to load existing signing key, generating new one")
	}

	// 生成新 RSA 密钥
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	s.key = key

	// 持久化密钥到数据库
	keyPEM, err := encodeRSAKey(key)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encode signing key")
		return nil
	}

	newKey := &model.Key{
		Type:      "oidc_signing_key",
		Value:     keyPEM,
		ExpiresAt: model.CustomTime{Time: time.Now().Add(365 * 24 * time.Hour)},
	}
	if err := s.keyRepo.Create(ctx, newKey); err != nil {
		log.Error().Err(err).Msg("Failed to persist signing key")
	}

	return nil
}

// parseRSAKey 解析 PEM 编码的 RSA 私钥
func parseRSAKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rsaKey, nil
}

// encodeRSAKey 编码 RSA 私钥为 PEM 格式
func encodeRSAKey(key *rsa.PrivateKey) (string, error) {
	bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// CheckUsernamePassword 验证用户名密码
func (s *Storage) CheckUsernamePassword(ctx context.Context, username, password string) (string, error) {
	user, err := s.userRepo.FindByInput(ctx, username)
	if err != nil {
		return "", ErrUnauthorizedUser
	}

	if user.PasswordHash == nil || *user.PasswordHash == "" {
		return "", ErrUnauthorizedUser
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(password)); err != nil {
		return "", ErrUnauthorizedUser
	}

	if !user.Approved || !user.EmailVerified || user.Disabled {
		return "", ErrUnauthorizedUser
	}

	return user.ID, nil
}

// --- op.OPStorage 接口实现 ---

// GetClientByClientID 获取客户端
// 优先从 clients 表读取（通过 Admin API 创建），如果没有再从 oidc_payloads 表读取（通过 OIDC API 创建）
func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	// 1. 首先尝试从 clients 表读取
	if s.clientRepo != nil {
		dbClient, err := s.clientRepo.FindByID(ctx, clientID)
		if err == nil && dbClient != nil {
			// 转换为 OIDC Client 格式
			var redirectURIs []string
			if dbClient.RedirectURIs != "" {
				json.Unmarshal([]byte(dbClient.RedirectURIs), &redirectURIs)
			}
			var scopes []string
			if dbClient.Scopes != "" {
				json.Unmarshal([]byte(dbClient.Scopes), &scopes)
			}
			var grantTypes []oidc.GrantType
			if dbClient.GrantTypes != "" {
				var gtStrings []string
				json.Unmarshal([]byte(dbClient.GrantTypes), &gtStrings)
				for _, gt := range gtStrings {
					grantTypes = append(grantTypes, oidc.GrantType(gt))
				}
			}
			var responseTypes []oidc.ResponseType
			if dbClient.ResponseTypes != "" {
				var rtStrings []string
				json.Unmarshal([]byte(dbClient.ResponseTypes), &responseTypes)
				for _, rt := range rtStrings {
					responseTypes = append(responseTypes, oidc.ResponseType(rt))
				}
			}

			return &Client{
				ID_:                     dbClient.ID,
				Secret_:                 ptrToString(dbClient.Secret),
				Name_:                   dbClient.Name,
				RedirectURIs_:           redirectURIs,
				PostLogoutRedirectURIs_: []string{},
				ApplicationType_:        op.ApplicationTypeWeb,
				ResponseTypes_:          responseTypes,
				GrantTypes_:             grantTypes,
				AccessTokenType_:        op.AccessTokenTypeBearer,
				IDTokenLifetime_:        30 * 60 * 1000000000, // 30 分钟
				DevMode_:                false,
				ClockSkew_:              0,
				Scopes_:                 scopes,
				SkipConsent_:            dbClient.Trusted,
				Trusted_:                dbClient.Trusted,
			}, nil
		}
	}

	// 2. 如果 clients 表没有，尝试从 oidc_payloads 表读取
	payload, err := s.oidcRepo.FindByIDAndType(ctx, clientID, "client")
	if err != nil {
		return nil, ErrInvalidClient
	}

	var client Client
	if err := json.Unmarshal([]byte(payload.Payload), &client); err != nil {
		return nil, err
	}

	return &client, nil
}

// ptrToString safely dereferences a string pointer
func ptrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// AuthorizeClientIDSecret 验证客户端密钥
func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	client, err := s.GetClientByClientID(ctx, clientID)
	if err != nil {
		return err
	}

	c := client.(*Client)
	if c.Secret_ == "" {
		return ErrInvalidClient
	}

	if err := bcrypt.CompareHashAndPassword([]byte(c.Secret_), []byte(clientSecret)); err != nil {
		return ErrInvalidClient
	}

	return nil
}

// SetUserinfoFromScopes 从范围设置用户信息
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeOpenID:
			userinfo.Subject = userID
		case oidc.ScopeProfile:
			userinfo.Name = ptrStringStr(user.Name)
			userinfo.PreferredUsername = user.Username
		case oidc.ScopeEmail:
			userinfo.Email = ptrStringStr(user.Email)
			userinfo.EmailVerified = oidc.Bool(user.EmailVerified)
		}
	}

	return nil
}

// SetUserinfoFromToken 从令牌设置用户信息
func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	return s.SetUserinfoFromScopes(ctx, userinfo, subject, "", []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail})
}

// SetIntrospectionFromToken 从令牌设置内省信息
func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	introspection.Active = true
	introspection.Subject = subject
	return nil
}

// GetPrivateClaimsFromScopes 获取私有声明
func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]interface{}, error) {
	claims := make(map[string]interface{})
	return claims, nil
}

// GetKeyByIDAndClientID 获取客户端密钥
func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, errors.New("not implemented")
}

// ValidateJWTProfileScopes 验证 JWT Profile 范围
func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return scopes, nil
}

// --- op.AuthStorage 接口实现 ---

// CreateAuthRequest 创建授权请求
func (s *Storage) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	id, err := generateID()
	if err != nil {
		return nil, err
	}
	req := &AuthRequest{
		AuthRequest: *authReq,
		ID:          id,
		UserID:      userID,
		AuthTime:    time.Now(),
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	oidcPayload := &model.OIDCPayload{
		ID:        req.ID,
		Type:      "auth_request",
		Payload:   string(payload),
		AccountID: &userID,
		ExpiresAt: ptrCustomTime(time.Now().Add(15 * time.Minute)),
	}

	if err := s.oidcRepo.Create(ctx, oidcPayload); err != nil {
		return nil, err
	}

	return req, nil
}

// AuthRequestByID 根据ID获取授权请求
func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	payload, err := s.oidcRepo.FindByIDAndType(ctx, id, "auth_request")
	if err != nil {
		return nil, ErrInvalidRequest
	}

	var req AuthRequest
	if err := json.Unmarshal([]byte(payload.Payload), &req); err != nil {
		return nil, err
	}

	return &req, nil
}

// AuthRequestByCode 根据授权码获取授权请求
func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	payload, err := s.oidcRepo.FindByIDAndType(ctx, code, "auth_code")
	if err != nil {
		return nil, ErrInvalidRequest
	}

	var req AuthRequest
	if err := json.Unmarshal([]byte(payload.Payload), &req); err != nil {
		return nil, err
	}

	return &req, nil
}

// SaveAuthCode 保存授权码
func (s *Storage) SaveAuthCode(ctx context.Context, id, code string) error {
	payload, err := s.oidcRepo.FindByIDAndType(ctx, id, "auth_request")
	if err != nil {
		return err
	}

	oidcPayload := &model.OIDCPayload{
		ID:        code,
		Type:      "auth_code",
		Payload:   payload.Payload,
		AccountID: payload.AccountID,
		ExpiresAt: ptrCustomTime(time.Now().Add(10 * time.Minute)),
	}

	return s.oidcRepo.Create(ctx, oidcPayload)
}

// DeleteAuthRequest 删除授权请求
func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.oidcRepo.Delete(ctx, id, "auth_request")
}

// CompleteAuthRequest 完成授权请求
func (s *Storage) CompleteAuthRequest(ctx context.Context, authRequestID, userID string) error {
	payload, err := s.oidcRepo.FindByIDAndType(ctx, authRequestID, "auth_request")
	if err != nil {
		return err
	}

	var req AuthRequest
	if err := json.Unmarshal([]byte(payload.Payload), &req); err != nil {
		return err
	}

	req.UserID = userID
	req.Done_ = true
	req.AuthTime = time.Now()

	updatedPayload, err := json.Marshal(req)
	if err != nil {
		return err
	}

	payload.Payload = string(updatedPayload)
	payload.AccountID = &userID

	return s.oidcRepo.Update(ctx, payload)
}

// CreateAccessToken 创建访问令牌
func (s *Storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (string, time.Time, error) {
	tokenID, err := generateID()
	if err != nil {
		return "", time.Time{}, err
	}
	exp := time.Now().Add(s.cfg.OIDC.AccessTokenTTL)

	token := &AccessToken{
		ID:        tokenID,
		UserID:    req.GetSubject(),
		ExpiresAt: exp,
	}

	payload, err := json.Marshal(token)
	if err != nil {
		return "", time.Time{}, err
	}

	oidcPayload := &model.OIDCPayload{
		ID:        tokenID,
		Type:      "access_token",
		Payload:   string(payload),
		AccountID: ptrString(req.GetSubject()),
		ExpiresAt: ptrCustomTime(exp),
	}

	if err := s.oidcRepo.Create(ctx, oidcPayload); err != nil {
		return "", time.Time{}, err
	}

	return tokenID, exp, nil
}

// CreateAccessAndRefreshTokens 创建访问令牌和刷新令牌
func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	accessToken, exp, err := s.CreateAccessToken(ctx, req)
	if err != nil {
		return "", "", time.Time{}, err
	}

	refreshToken, err := generateID()
	if err != nil {
		return "", "", time.Time{}, err
	}
	refreshExp := time.Now().Add(s.cfg.OIDC.RefreshTokenTTL)

	token := &AccessToken{
		ID:        refreshToken,
		UserID:    req.GetSubject(),
		ExpiresAt: refreshExp,
	}

	payload, _ := json.Marshal(token)
	oidcPayload := &model.OIDCPayload{
		ID:        refreshToken,
		Type:      "refresh_token",
		Payload:   string(payload),
		AccountID: ptrString(req.GetSubject()),
		ExpiresAt: ptrCustomTime(refreshExp),
	}

	_ = s.oidcRepo.Create(ctx, oidcPayload)

	return accessToken, refreshToken, exp, nil
}

// TokenRequestByRefreshToken 根据刷新令牌获取令牌请求
func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	payload, err := s.oidcRepo.FindByIDAndType(ctx, refreshToken, "refresh_token")
	if err != nil {
		return nil, ErrInvalidGrant
	}

	var token AccessToken
	if err := json.Unmarshal([]byte(payload.Payload), &token); err != nil {
		return nil, err
	}

	return &RefreshToken{
		ID:        refreshToken,
		UserID:    token.UserID,
		ExpiresAt: token.ExpiresAt,
	}, nil
}

// --- op.KeyStorage 接口实现 ---

// SigningKey 获取签名密钥
func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	return &SigningKey{key: s.key}, nil
}

// SignatureAlgorithms 获取签名算法
func (s *Storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet 获取密钥集
func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	return []op.Key{
		&PublicKey{id: "key-1", key: &s.key.PublicKey},
	}, nil
}

// Health 健康检查
func (s *Storage) Health(ctx context.Context) error {
	return nil
}

// TerminateSession 终止会话（登出传播）
// 删除用户的所有 session，实现 OIDC 单点登出
func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	if userID == "" {
		return nil
	}

	// 删除用户的所有 session（实现完整的 SSO 登出）
	if s.sessionRepo != nil {
		if err := s.sessionRepo.DeleteByUserID(ctx, userID); err != nil {
			log.Error().Err(err).Str("userID", userID).Msg("Failed to delete user sessions")
		}
	}

	// 清理 OIDC 相关的 tokens
	tokens, err := s.oidcRepo.FindByAccountID(ctx, userID)
	if err != nil {
		log.Debug().Err(err).Str("userID", userID).Msg("Failed to find tokens for termination")
		return nil
	}

	for _, token := range tokens {
		if token.Type == "access_token" || token.Type == "refresh_token" {
			if err := s.oidcRepo.Delete(ctx, token.ID, token.Type); err != nil {
				log.Debug().Err(err).Str("tokenID", token.ID).Msg("Failed to delete token")
			}
		}
	}

	log.Info().Str("userID", userID).Msg("Session terminated")
	return nil
}

// RevokeToken 撤销令牌
func (s *Storage) RevokeToken(ctx context.Context, tokenOrRefreshTokenID string, userID string, clientID string) *oidc.Error {
	_ = s.oidcRepo.Delete(ctx, tokenOrRefreshTokenID, "refresh_token")
	_ = s.oidcRepo.Delete(ctx, tokenOrRefreshTokenID, "access_token")
	return nil
}

// GetRefreshTokenInfo 获取刷新令牌信息
func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	payload, err := s.oidcRepo.FindByIDAndType(ctx, token, "refresh_token")
	if err != nil {
		return "", "", ErrInvalidGrant
	}

	var tokenData AccessToken
	if err := json.Unmarshal([]byte(payload.Payload), &tokenData); err != nil {
		return "", "", err
	}

	return tokenData.ID, tokenData.UserID, nil
}

// --- 数据类型 ---

// AuthRequest 授权请求
type AuthRequest struct {
	oidc.AuthRequest
	ID       string    `json:"ID"`
	UserID   string    `json:"UserID"`
	AuthTime time.Time `json:"authTime"`
	Done_    bool      `json:"done"`
}

func (a *AuthRequest) GetID() string                        { return a.ID }
func (a *AuthRequest) GetACR() string                       { return "" }
func (a *AuthRequest) GetAMR() []string                     { return []string{"pwd"} }
func (a *AuthRequest) GetAudience() []string                { return []string{a.ClientID} }
func (a *AuthRequest) GetAuthTime() time.Time               { return a.AuthTime }
func (a *AuthRequest) GetClientID() string                  { return a.ClientID }
func (a *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge { return nil }
func (a *AuthRequest) GetNonce() string                     { return a.Nonce }
func (a *AuthRequest) GetRedirectURI() string               { return a.RedirectURI }
func (a *AuthRequest) GetResponseType() oidc.ResponseType   { return a.ResponseType }
func (a *AuthRequest) GetResponseMode() oidc.ResponseMode   { return "" }
func (a *AuthRequest) GetScopes() []string                  { return a.Scopes }
func (a *AuthRequest) GetState() string                     { return a.State }
func (a *AuthRequest) GetSubject() string                   { return a.UserID }
func (a *AuthRequest) Done() bool                           { return a.Done_ }
func (a *AuthRequest) SetCurrentScopes(scopes []string)     {}

// AccessToken 访问令牌
type AccessToken struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// RefreshToken 刷新令牌
type RefreshToken struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (r *RefreshToken) GetAMR() []string        { return nil }
func (r *RefreshToken) GetAudience() []string  { return nil }
func (r *RefreshToken) GetAuthTime() time.Time { return time.Now() }
func (r *RefreshToken) GetClientID() string    { return "" }
func (r *RefreshToken) GetScopes() []string    { return nil }
func (r *RefreshToken) GetSubject() string     { return r.UserID }
func (r *RefreshToken) SetCurrentScopes(scopes []string) {}

// SigningKey 签名密钥
type SigningKey struct {
	key *rsa.PrivateKey
}

func (s *SigningKey) ID() string                            { return "key-1" }
func (s *SigningKey) Key() interface{}                      { return s.key }
func (s *SigningKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }

// PublicKey 公钥
type PublicKey struct {
	id  string
	key *rsa.PublicKey
}

func (p *PublicKey) ID() string                             { return p.id }
func (p *PublicKey) Key() interface{}                       { return p.key }
func (p *PublicKey) Use() string                            { return "sig" }
func (p *PublicKey) Algorithm() jose.SignatureAlgorithm     { return jose.RS256 }

// Client OIDC 客户端
type Client struct {
	ID_                     string              `json:"id"`
	Secret_                 string              `json:"secret"`
	Name_                   string              `json:"name"`
	RedirectURIs_           []string            `json:"redirectUris"`
	PostLogoutRedirectURIs_ []string            `json:"postLogoutRedirectUris"`
	ApplicationType_        op.ApplicationType  `json:"applicationType"`
	ResponseTypes_          []oidc.ResponseType `json:"responseTypes"`
	GrantTypes_             []oidc.GrantType    `json:"grantTypes"`
	AccessTokenType_        op.AccessTokenType  `json:"accessTokenType"`
	IDTokenLifetime_        time.Duration       `json:"idTokenLifetime"`
	DevMode_                bool                `json:"devMode"`
	ClockSkew_              time.Duration       `json:"clockSkew"`
	Scopes_                 []string            `json:"scopes"`
	SkipConsent_            bool                `json:"skipConsent"`
	Trusted_                bool                `json:"trusted"`
}

func (c *Client) GetID() string                                  { return c.ID_ }
func (c *Client) RedirectURIs() []string                         { return c.RedirectURIs_ }
func (c *Client) PostLogoutRedirectURIs() []string               { return c.PostLogoutRedirectURIs_ }
func (c *Client) ApplicationType() op.ApplicationType            { return c.ApplicationType_ }
func (c *Client) AuthMethod() oidc.AuthMethod                    { return oidc.AuthMethodBasic }
func (c *Client) ResponseTypes() []oidc.ResponseType             { return c.ResponseTypes_ }
func (c *Client) GrantTypes() []oidc.GrantType                   { return c.GrantTypes_ }
func (c *Client) LoginURL(authRequestID string) string           { return "/interaction?authRequestID=" + authRequestID }
func (c *Client) AccessTokenType() op.AccessTokenType            { return c.AccessTokenType_ }
func (c *Client) IDTokenLifetime() time.Duration                 { return c.IDTokenLifetime_ }
func (c *Client) DevMode() bool                                  { return c.DevMode_ }
func (c *Client) AllowedScopes() []string                        { return c.Scopes_ }
func (c *Client) GetName() string                                { return c.Name_ }
func (c *Client) LogoURI() string                                { return "" }
func (c *Client) ClientURI() string                              { return "" }
func (c *Client) SkipConsent() bool                              { return c.SkipConsent_ || c.Trusted_ }
func (c *Client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *Client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *Client) IsScopeAllowed(scope string) bool {
	for _, s := range c.Scopes_ {
		if s == scope {
			return true
		}
	}
	return false
}
func (c *Client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *Client) ClockSkew() time.Duration              { return c.ClockSkew_ }
func (c *Client) IDTokenSigningKeyID() string           { return "key-1" }

// 辅助函数
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

func ptrCustomTime(t time.Time) *model.CustomTime {
	return &model.CustomTime{Time: t}
}

func ptrString(s string) *string {
	return &s
}

func ptrStringStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
