package model

import "time"

// User 用户模型
type User struct {
	ID            string      `db:"id" json:"id"`
	Email         *string     `db:"email" json:"email"`
	Username      string      `db:"username" json:"username"`
	Name          *string     `db:"name" json:"name"`
	PasswordHash  *string     `db:"passwordHash" json:"-"`
	IsAdmin       bool        `db:"isAdmin" json:"isAdmin"`
	EmailVerified bool        `db:"emailVerified" json:"emailVerified"`
	Approved      bool        `db:"approved" json:"approved"`
	MFARequired   bool        `db:"mfaRequired" json:"mfaRequired"`
	Disabled      bool        `db:"disabled" json:"disabled"`
	CreatedAt     CustomTime  `db:"createdAt" json:"createdAt"`
	UpdatedAt     CustomTime  `db:"updatedAt" json:"updatedAt"`
}

// UserResponse 用户响应
type UserResponse struct {
	ID            string      `json:"id"`
	Email         *string     `json:"email"`
	Username      string      `json:"username"`
	Name          *string     `json:"name"`
	IsAdmin       bool        `json:"isAdmin"`
	EmailVerified bool        `json:"emailVerified"`
	Approved      bool        `json:"approved"`
	MFARequired   bool        `json:"mfaRequired"`
	Disabled      bool        `json:"disabled"`
	HasPassword   bool        `json:"hasPassword"`
	HasTotp       bool        `json:"hasTotp"`
	Groups        []*GroupRef `json:"groups"`
	CreatedAt     time.Time   `json:"createdAt"`
	UpdatedAt     time.Time   `json:"updatedAt"`
}

// GroupRef 组引用
type GroupRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ToResponse 转换为响应格式
func (u *User) ToResponse() *UserResponse {
	return &UserResponse{
		ID:            u.ID,
		Email:         u.Email,
		Username:      u.Username,
		Name:          u.Name,
		IsAdmin:       u.IsAdmin,
		EmailVerified: u.EmailVerified,
		Approved:      u.Approved,
		MFARequired:   u.MFARequired,
		Disabled:      u.Disabled,
		HasPassword:   u.PasswordHash != nil && *u.PasswordHash != "",
		HasTotp:       false,
		Groups:        []*GroupRef{},
		CreatedAt:     u.CreatedAt.Time,
		UpdatedAt:     u.UpdatedAt.Time,
	}
}

// Group 组模型
type Group struct {
	ID          string     `db:"id" json:"id"`
	Name        string     `db:"name" json:"name"`
	MFARequired bool       `db:"mfaRequired" json:"mfaRequired"`
	CreatedBy   string     `db:"createdBy" json:"createdBy"`
	CreatedAt   CustomTime `db:"createdAt" json:"createdAt"`
	UpdatedAt   CustomTime `db:"updatedAt" json:"updatedAt"`
}

// UserGroup 用户-组关联
type UserGroup struct {
	UserID    string     `db:"userId" json:"userId"`
	GroupID   string     `db:"groupId" json:"groupId"`
	CreatedAt CustomTime `db:"createdAt" json:"createdAt"`
}

// TOTP TOTP配置
type TOTP struct {
	ID        string     `db:"id" json:"id"`
	UserID    string     `db:"userId" json:"userId"`
	Secret    string     `db:"secret" json:"-"`
	CreatedAt CustomTime `db:"createdAt" json:"createdAt"`
	UpdatedAt CustomTime `db:"updatedAt" json:"updatedAt"`
}

// Key 密钥模型
type Key struct {
	ID        string     `db:"id" json:"id"`
	Type      string     `db:"type" json:"type"`
	Value     string     `db:"value" json:"-"`
	ExpiresAt CustomTime `db:"expiresAt" json:"expiresAt"`
	CreatedAt CustomTime `db:"createdAt" json:"createdAt"`
}

// Consent 授权同意
type Consent struct {
	UserID    string     `db:"userId" json:"userId"`
	ClientID  string     `db:"clientId" json:"clientId"`
	Scope     string     `db:"scope" json:"scope"`
	CreatedAt CustomTime `db:"createdAt" json:"createdAt"`
	ExpiresAt CustomTime `db:"expiresAt" json:"expiresAt"`
}

// Invitation 邀请
type Invitation struct {
	ID            string     `db:"id" json:"id"`
	Email         *string    `db:"email" json:"email"`
	Username      *string    `db:"username" json:"username"`
	Name          *string    `db:"name" json:"name"`
	Challenge     string     `db:"challenge" json:"-"`
	EmailVerified bool       `db:"emailVerified" json:"emailVerified"`
	CreatedBy     string     `db:"createdBy" json:"createdBy"`
	CreatedAt     CustomTime `db:"createdAt" json:"createdAt"`
	ExpiresAt     CustomTime `db:"expiresAt" json:"expiresAt"`
}

// InvitationGroup 邀请-组关联
type InvitationGroup struct {
	InvitationID string `db:"invitationId" json:"invitationId"`
	GroupID      string `db:"groupId" json:"groupId"`
}

// ProxyAuth 代理认证配置
type ProxyAuth struct {
	ID               string     `db:"id" json:"id"`
	Domain           string     `db:"domain" json:"domain"`
	MFARequired      bool       `db:"mfaRequired" json:"mfaRequired"`
	MaxSessionLength *int       `db:"maxSessionLength" json:"maxSessionLength"`
	CreatedBy        string     `db:"createdBy" json:"createdBy"`
	CreatedAt        CustomTime `db:"createdAt" json:"createdAt"`
	UpdatedAt        CustomTime `db:"updatedAt" json:"updatedAt"`
}

// ProxyAuthGroup 代理认证-组关联
type ProxyAuthGroup struct {
	ProxyAuthID string `db:"proxyAuthId" json:"proxyAuthId"`
	GroupID     string `db:"groupId" json:"groupId"`
}

// OIDCPayload OIDC Payloads
type OIDCPayload struct {
	ID         string      `db:"id" json:"id"`
	Type       string      `db:"type" json:"type"`
	Payload    string      `db:"payload" json:"payload"`
	GrantID    *string     `db:"grantId" json:"grantId"`
	UserCode   *string     `db:"userCode" json:"userCode"`
	UID        *string     `db:"uid" json:"uid"`
	ExpiresAt  *CustomTime `db:"expiresAt" json:"expiresAt"`
	ConsumedAt *CustomTime `db:"consumedAt" json:"consumedAt"`
	AccountID  *string     `db:"accountId" json:"accountId"`
}

// Flag 系统标志
type Flag struct {
	Name      string     `db:"name" json:"name"`
	Value     *string    `db:"value" json:"value"`
	CreatedAt CustomTime `db:"createdAt" json:"createdAt"`
}

// Session 会话模型
type Session struct {
	ID                string     `db:"id" json:"id"`
	UserID            string     `db:"userId" json:"userId"`
	Token             string     `db:"token" json:"-"`
	AMR               string     `db:"amr" json:"amr"` // Authentication Methods References
	TotpAttempts      int        `db:"totpAttempts" json:"totpAttempts"` // TOTP 尝试次数
	RememberMe        bool       `db:"rememberMe" json:"rememberMe"`
	ExpiresAt         CustomTime `db:"expiresAt" json:"expiresAt"`
	CreatedAt         CustomTime `db:"createdAt" json:"createdAt"`
	LastRefreshedAt   CustomTime `db:"lastRefreshedAt" json:"-"` // 最近一次滑动续期时间
}

// Client OIDC客户端模型
type Client struct {
	ID                string     `db:"id" json:"id"`
	Name              string     `db:"name" json:"name"`
	Secret            *string    `db:"secret" json:"-"`
	RedirectURIs      string     `db:"redirectUris" json:"redirectUris"`      // JSON array
	PostLogoutURIs    string     `db:"postLogoutUris" json:"postLogoutUris"`  // JSON array
	Scopes            string     `db:"scopes" json:"scopes"`                  // JSON array
	GrantTypes        string     `db:"grantTypes" json:"grantTypes"`          // JSON array
	ResponseTypes     string     `db:"responseTypes" json:"responseTypes"`    // JSON array
	TokenEndpointAuth string     `db:"tokenEndpointAuth" json:"tokenEndpointAuth"`
	Trusted           bool       `db:"trusted" json:"trusted"` // 可信客户端，自动授权
	CreatedBy         string     `db:"createdBy" json:"createdBy"`
	CreatedAt         CustomTime `db:"createdAt" json:"createdAt"`
	UpdatedAt         CustomTime `db:"updatedAt" json:"updatedAt"`
}

// ClientResponse 客户端响应
type ClientResponse struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	HasSecret         bool     `json:"hasSecret"`
	RedirectURIs      []string `json:"redirectUris"`
	PostLogoutURIs    []string `json:"postLogoutUris"`
	Scopes            []string `json:"scopes"`
	GrantTypes        []string `json:"grantTypes"`
	ResponseTypes     []string `json:"responseTypes"`
	TokenEndpointAuth string   `json:"tokenEndpointAuth"`
	Trusted           bool     `json:"trusted"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// LoginAttempt 登录尝试记录（暴力破解防护）
type LoginAttempt struct {
	ID        string     `db:"id" json:"id"`
	Username  string     `db:"username" json:"username"`
	IP        string     `db:"ip" json:"ip"`
	Success   bool       `db:"success" json:"success"`
	CreatedAt CustomTime `db:"createdAt" json:"createdAt"`
}

// AuditLog 审计日志
type AuditLog struct {
	ID        string     `db:"id" json:"id"`
	Action    string     `db:"action" json:"action"`
	ActorID   *string    `db:"actorId" json:"actorId"`
	TargetID  *string    `db:"targetId" json:"targetId"`
	Details   string     `db:"details" json:"details"` // JSON
	IP        string     `db:"ip" json:"ip"`
	CreatedAt CustomTime `db:"createdAt" json:"createdAt"`
}

// Audit actions
const (
	AuditActionLogin         = "login"
	AuditActionLogout        = "logout"
	AuditActionRegister      = "register"
	AuditActionPasswordReset = "password_reset"
	AuditActionUserApproved  = "user_approved"
	AuditActionUserDisabled  = "user_disabled"
	AuditActionUserDeleted   = "user_deleted"
	AuditActionGroupCreated  = "group_created"
	AuditActionGroupDeleted  = "group_deleted"
	AuditActionClientCreated = "client_created"
	AuditActionClientDeleted = "client_deleted"
)
