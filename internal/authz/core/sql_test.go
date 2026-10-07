package core

import (
	"database/sql/driver"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMultiInsertStmt(t *testing.T) {
	t.Run("multiInsertStmt1", func(t *testing.T) {
		expected := "INSERT INTO test(a, b) VALUES ($1, $2)"
		assert.Equal(t, MultiInsertStmt("test(a, b)", 1), expected)
	})
	t.Run("multiInsertStmt2", func(t *testing.T) {
		expected := "INSERT INTO test(a, b) VALUES ($1, $2), ($3, $4)"
		assert.Equal(t, MultiInsertStmt("test(a, b)", 2), expected)
	})
}

func TestSelectInStmtBindsValues(t *testing.T) {
	payload := "x'); DROP TABLE role; --"
	query, arg := SelectInStmt("role", "name", []string{payload})
	assert.Equal(t, "SELECT role.* FROM role WHERE name = ANY($1)", query)
	assert.NotContains(t, query, payload)
	value, err := arg.(driver.Valuer).Value()
	assert.NoError(t, err)
	assert.True(t, strings.Contains(value.(string), payload))
}
