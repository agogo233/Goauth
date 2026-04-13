package util

import (
	"crypto/rand"
	"errors"
	"strings"

	"github.com/nbutton23/zxcvbn-go"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrPasswordTooShort   = errors.New("密码太短")
	ErrPasswordTooWeak    = errors.New("密码强度不足")
	ErrPasswordHashFailed = errors.New("密码哈希失败")
	ErrEmailInvalid       = errors.New("邮箱格式无效")
)

// HashPassword 哈希密码
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", ErrPasswordHashFailed
	}
	return string(hash), nil
}

// VerifyPassword 验证密码
func VerifyPassword(password, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CheckPasswordStrength 检查密码强度
// minLen: 最小长度
// minScore: 最小强度分数 (0-4)
func CheckPasswordStrength(password string, minLen, minScore int) error {
	if len(password) < minLen {
		return ErrPasswordTooShort
	}

	result := zxcvbn.PasswordStrength(password, nil)
	if result.Score < minScore {
		return ErrPasswordTooWeak
	}

	return nil
}

// PasswordScore 返回密码强度分数 (0-4)
func PasswordScore(password string) int {
	result := zxcvbn.PasswordStrength(password, nil)
	return result.Score
}

// GenerateRandomPassword 生成随机密码
func GenerateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}

// IsValidEmail 验证邮箱格式是否有效
// 空邮箱返回 true（允许不提供邮箱）
// 使用简单有效的格式检查，不追求完美覆盖所有 RFC 5322 案例
func IsValidEmail(email string) bool {
	if email == "" {
		return true // 空邮箱允许
	}

	// 基本格式检查
	// 1. 必须包含 @ 且 @ 不在首尾
	at := strings.Index(email, "@")
	if at <= 0 || at >= len(email)-1 {
		return false
	}

	// 2. @ 后面的域名部分必须包含至少一个点
	domain := email[at+1:]
	dot := strings.LastIndex(domain, ".")
	if dot <= 0 || dot >= len(domain)-1 {
		return false
	}

	// 3. 不能有连续的点
	if strings.Contains(email, "..") {
		return false
	}

	// 4. 本地部分（@ 前）不能为空
	local := email[:at]
	if len(local) == 0 {
		return false
	}

	return true
}
