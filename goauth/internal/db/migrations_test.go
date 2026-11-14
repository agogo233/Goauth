package db

import (
	"testing"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
)

func TestRunMigrations_Versioned(t *testing.T) {
	db, err := sqlx.Open("sqlite3", ":memory:?_foreign_keys=on")
	require.NoError(t, err)
	defer db.Close()

	require.NoError(t, RunMigrations(db))
	// 重复执行应幂等
	require.NoError(t, RunMigrations(db))

	var count int
	require.NoError(t, db.Get(&count, `SELECT COUNT(*) FROM schema_migrations WHERE version = 1`))
	require.Equal(t, 1, count, "版本 1 应只记录一次")
}
