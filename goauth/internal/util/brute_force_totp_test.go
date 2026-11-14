package util

import (
	"context"
	"testing"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	dbpkg "goauth/internal/db"
)

func TestBruteForceProtector_TotpIndependentThreshold(t *testing.T) {
	db, err := sqlx.Open("sqlite3", ":memory:?_foreign_keys=on")
	require.NoError(t, err)
	require.NoError(t, dbpkg.RunMigrations(db))
	defer db.Close()

	// 登录阈值 10，TOTP 阈值 5
	p := NewBruteForceProtector(db, 10, 30, 5)
	ctx := context.Background()

	// 4 次失败：TOTP 未封锁
	for i := 0; i < 4; i++ {
		require.NoError(t, p.RecordTotpAttempt(ctx, "user1", "1.1.1.1", false))
	}
	blocked, err := p.IsTotpBlocked(ctx, "user1", "1.1.1.1")
	require.NoError(t, err)
	require.False(t, blocked, "4 次失败不应封锁 TOTP")

	// 第 5 次失败：TOTP 封锁（但登录阈值 10 未触发）
	require.NoError(t, p.RecordTotpAttempt(ctx, "user1", "1.1.1.1", false))
	blocked, err = p.IsTotpBlocked(ctx, "user1", "1.1.1.1")
	require.NoError(t, err)
	require.True(t, blocked, "第 5 次失败应按 TOTP 独立阈值封锁")

	// 普通登录封禁不应被触发（4+1=5 < 10）
	ib, err := p.IsBlocked(ctx, "user1", "1.1.1.1")
	require.NoError(t, err)
	require.False(t, ib, "TOTP 失败不应触发登录 IP 封锁（5<10）")

	// totpMaxAttempts<=0 时回退为 maxAttempts
	p2 := NewBruteForceProtector(db, 10, 30, 0)
	require.Equal(t, 10, p2.totpMaxAttempts)
}
