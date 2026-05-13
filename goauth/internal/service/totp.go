package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"

	"goauth/internal/config"
	"goauth/internal/model"
	"goauth/internal/util"
)

var (
	ErrTotpNotEnabled     = errors.New("TOTP 未启用")
	ErrTotpAlreadyEnabled = errors.New("TOTP 已启用")
)

// TotpService TOTP 服务
type TotpService struct {
	db       *sqlx.DB
	cfg      *config.Config
}

// NewTotpService 创建 TOTP 服务
func NewTotpService(db *sqlx.DB, cfg *config.Config) *TotpService {
	return &TotpService{
		db:  db,
		cfg: cfg,
	}
}

// TotpSetupResponse TOTP 设置响应
type TotpSetupResponse struct {
	URI             string `json:"uri"`
	QrBase64        string `json:"qrBase64"`
	Secret          string `json:"secret"`
	EncryptedSecret string `json:"encryptedSecret"` // 加密后的密钥，用于验证时存储
}

// Setup 为用户设置 TOTP（生成密钥但不存储，等验证成功后再存储）
func (s *TotpService) Setup(ctx context.Context, userID, username string) (*TotpSetupResponse, error) {
	// 检查是否已启用
	var count int
	err := s.db.GetContext(ctx, &count, `SELECT COUNT(*) FROM totp WHERE userId = ?`, userID)
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, ErrTotpAlreadyEnabled
	}

	// 生成 TOTP 密钥
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.cfg.UI.AppName,
		AccountName: username,
	})
	if err != nil {
		return nil, err
	}

	// 生成 QR 码
	qrPng, err := qrcode.Encode(key.String(), qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}

	// 加密密钥（用于前端传递回来，验证成功后存储）
	encryptedSecret, err := util.Encrypt(key.Secret(), s.cfg.Security.CryptoKey)
	if err != nil {
		return nil, err
	}

	// 注意：不在此处存储，等用户验证成功后再存储
	return &TotpSetupResponse{
		URI:             key.String(),
		QrBase64:        base64.StdEncoding.EncodeToString(qrPng),
		Secret:          key.Secret(),
		EncryptedSecret: encryptedSecret,
	}, nil
}

// VerifySetupCode 验证设置 TOTP 时的验证码（使用明文密钥验证）
func (s *TotpService) VerifySetupCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// ConfirmSetup 确认 TOTP 设置，存储密钥
func (s *TotpService) ConfirmSetup(ctx context.Context, userID, encryptedSecret string) error {
	now := model.Now()
	totpRecord := &model.TOTP{
		ID:        uuid.NewString(),
		UserID:    userID,
		Secret:    encryptedSecret,
		CreatedAt: now,
		UpdatedAt: now,
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO totp (id, userId, secret, createdAt, updatedAt)
		VALUES (?, ?, ?, ?, ?)
	`, totpRecord.ID, totpRecord.UserID, totpRecord.Secret, totpRecord.CreatedAt, totpRecord.UpdatedAt)
	return err
}

// Verify 验证 TOTP 代码
func (s *TotpService) Verify(ctx context.Context, userID, code string) (bool, error) {
	// 获取 TOTP 配置
	var encryptedSecret string
	err := s.db.GetContext(ctx, &encryptedSecret, `SELECT secret FROM totp WHERE userId = ?`, userID)
	if err != nil {
		return false, ErrTotpNotEnabled
	}

	// 解密密钥
	secret, err := util.Decrypt(encryptedSecret, s.cfg.Security.CryptoKey)
	if err != nil {
		return false, err
	}

	// 验证代码
	valid := totp.Validate(code, secret)
	return valid, nil
}

// Remove 移除 TOTP
func (s *TotpService) Remove(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM totp WHERE userId = ?`, userID)
	return err
}

// IsEnabled 检查是否启用 TOTP
func (s *TotpService) IsEnabled(ctx context.Context, userID string) (bool, error) {
	var count int
	err := s.db.GetContext(ctx, &count, `SELECT COUNT(*) FROM totp WHERE userId = ?`, userID)
	return count > 0, err
}

// GenerateBackupCodes 生成并存储 TOTP 备用码
func (s *TotpService) GenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := 0; i < 10; i++ {
		b := make([]byte, 4)
		rand.Read(b)
		codes[i] = fmt.Sprintf("%s-%s",
			base64.RawURLEncoding.EncodeToString(b[:2]),
			base64.RawURLEncoding.EncodeToString(b[2:]))
		hash, err := util.HashPassword(codes[i])
		if err != nil {
			return nil, err
		}
		hashes[i] = hash
	}

	data, err := json.Marshal(hashes)
	if err != nil {
		return nil, err
	}

	now := model.Now()
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO totp_backup_codes (userId, codesHash, createdAt)
		VALUES (?, ?, ?)
		ON CONFLICT(userId) DO UPDATE SET codesHash = ?, createdAt = ?
	`, userID, string(data), now, string(data), now)
	if err != nil {
		return nil, err
	}

	return codes, nil
}

// ValidateBackupCode 验证 TOTP 备用码，验证通过后该码作废
func (s *TotpService) ValidateBackupCode(ctx context.Context, userID, code string) (bool, error) {
	var codesHash string
	err := s.db.GetContext(ctx, &codesHash, `SELECT codesHash FROM totp_backup_codes WHERE userId = ?`, userID)
	if err != nil {
		return false, err
	}

	var hashes []string
	if err := json.Unmarshal([]byte(codesHash), &hashes); err != nil {
		return false, err
	}

	for i, h := range hashes {
		if h != "" {
			valid, err := util.VerifyPassword(code, h)
			if err == nil && valid {
				// 作废已使用的备用码
				hashes[i] = ""
				data, _ := json.Marshal(hashes)
				s.db.ExecContext(ctx, `UPDATE totp_backup_codes SET codesHash = ? WHERE userId = ?`, data, userID)
				return true, nil
			}
		}
	}
	return false, nil
}

// ValidateUri 验证 otpauth URI
func ValidateUri(uri string) (*otp.Key, error) {
	return otp.NewKeyFromURL(uri)
}

// ParseSecretFromUri 从 URI 解析密钥
func ParseSecretFromUri(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	
	query := u.Query()
	return query.Get("secret"), nil
}
