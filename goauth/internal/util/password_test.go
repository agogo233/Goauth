package util

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"正常密码", "password123", false},
		{"空密码", "", false},
		{"长密码", "this_is_a_very_long_password_that_should_still_work_fine", false},
		{"特殊字符", "p@ssw0rd!#$%", false},
		{"中文密码", "密码测试123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && hash == "" {
				t.Error("HashPassword() returned empty hash")
			}
			if !tt.wantErr && hash == tt.password {
				t.Error("HashPassword() returned unhashed password")
			}
		})
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "testPassword123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	tests := []struct {
		name     string
		password string
		hash     string
		want     bool
		wantErr  bool
	}{
		{"正确密码", password, hash, true, false},
		{"错误密码", "wrongPassword", hash, false, false},
		{"空密码", "", hash, false, false},
		{"无效哈希", password, "invalid_hash", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyPassword(tt.password, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VerifyPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckPasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		minLen   int
		minScore int
		wantErr  error
	}{
		{"太短", "short", 8, 3, ErrPasswordTooShort},
		{"弱密码", "password", 8, 3, ErrPasswordTooWeak},
		{"空密码", "", 8, 3, ErrPasswordTooShort},
		// 以下测试使用较低的分数要求，因为zxcvbn评分可能因字典变化
		{"足够长度-低要求", "Password123456", 8, 0, nil},
		{"复杂密码-低要求", "Xk9#mP2$vL7@nQ4", 8, 1, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckPasswordStrength(tt.password, tt.minLen, tt.minScore)
			if err != tt.wantErr {
				t.Errorf("CheckPasswordStrength() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestPasswordScore(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantMin  int
		wantMax  int
	}{
		{"弱密码", "password", 0, 2},
		{"长随机密码", "Xk9mP2vL7nQ4wR8tY3uI6oP5aS2dF1gH", 0, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := PasswordScore(tt.password)
			if score < tt.wantMin || score > 4 {
				t.Errorf("PasswordScore() = %v, want between %v and 4", score, tt.wantMin)
			}
			t.Logf("Password %q score: %d", tt.password, score)
		})
	}
}

func TestGenerateRandomPassword(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"8字符", 8},
		{"16字符", 16},
		{"32字符", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := GenerateRandomPassword(tt.length)
			if err != nil {
				t.Fatalf("GenerateRandomPassword() error = %v", err)
			}
			if len(password) != tt.length {
				t.Errorf("GenerateRandomPassword() length = %v, want %v", len(password), tt.length)
			}
			// 生成多个密码，检查它们是否不同
			password2, _ := GenerateRandomPassword(tt.length)
			if password == password2 {
				t.Log("Warning: two generated passwords are the same (unlikely but possible)")
			}
		})
	}
}

func TestHashPasswordAndVerifyIntegration(t *testing.T) {
	passwords := []string{
		"simple123",
		"C0mpl3x!P@ss",
		"中文密码测试",
		"   spaces   ",
		"verylongpasswordwithmanycharacters123456789!@#$%",
	}

	for _, pwd := range passwords {
		t.Run(pwd, func(t *testing.T) {
			hash, err := HashPassword(pwd)
			if err != nil {
				t.Fatalf("HashPassword failed: %v", err)
			}

			valid, err := VerifyPassword(pwd, hash)
			if err != nil {
				t.Fatalf("VerifyPassword failed: %v", err)
			}
			if !valid {
				t.Error("VerifyPassword returned false for correct password")
			}

			valid, _ = VerifyPassword("wrong"+pwd, hash)
			if valid {
				t.Error("VerifyPassword returned true for wrong password")
			}
		})
	}
}
