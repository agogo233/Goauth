package repo

import (
	"context"
	"testing"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	dbpkg "goauth/internal/db"
	"goauth/internal/model"
)

func TestUserRepo_EmptyEmailUnique(t *testing.T) {
	db, err := sqlx.Open("sqlite3", ":memory:?_foreign_keys=on")
	require.NoError(t, err)
	require.NoError(t, dbpkg.RunMigrations(db))
	r := NewUserRepo(db)
	ctx := context.Background()

	// 两个用户都不带邮箱（NULL），不应触发 UNIQUE 冲突
	u1 := &model.User{Username: "noemail1"}
	require.NoError(t, r.Create(ctx, u1))
	u2 := &model.User{Username: "noemail2", Email: strPtr("")}
	require.NoError(t, r.Create(ctx, u2), "空邮箱应归一为 NULL，不触发 UNIQUE 冲突")

	// 相同邮箱（大小写不同）应冲突
	u3 := &model.User{Username: "withemail", Email: strPtr("A@B.com")}
	require.NoError(t, r.Create(ctx, u3))
	u4 := &model.User{Username: "withemail2", Email: strPtr("a@b.com")}
	err = r.Create(ctx, u4)
	require.Error(t, err, "大小写不同的相同邮箱应触发 UNIQUE 冲突")
}

func strPtr(s string) *string { return &s }
