package core

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/lib/pq"
)

// multiInsertStmt generates a string for a SQL command to insert multiple rows
// into a table.
//
//	multiInsertStmt("table(col1, col2)", 2)
//	== "INSERT INTO table(col1, col2) VALUES ($1, $2), ($3, $4)"
func MultiInsertStmt(table string, n_rows int) string {
	parse_values := strings.Split(table, "(")
	half_parsed := parse_values[len(parse_values)-1]
	parse_values = strings.Split(half_parsed, ")")
	values := strings.Split(parse_values[0], ",")
	n_values := len(values)

	rowsString := ""

	x := 1
	for i := 1; i <= n_rows; i++ {
		rowsString += "("
		for j := 1; j <= n_values; j++ {
			rowsString += "$"
			rowsString += strconv.Itoa(x)
			rowsString += ", "
			x++
		}
		rowsString = strings.TrimRight(rowsString, ", ")
		rowsString += "), "
	}
	rowsString = strings.TrimRight(rowsString, ", ")

	return fmt.Sprintf("INSERT INTO %s VALUES %s", table, rowsString)
}

// Table and column are trusted identifiers; values are bound as a parameter.
func SelectInStmt(table string, col string, values []string) (string, interface{}) {
	stmt := fmt.Sprintf("SELECT %s.* FROM %s WHERE %s = ANY($1)", table, table, col)
	return stmt, pq.Array(values)
}
