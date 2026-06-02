package arborist

import (
	"strings"

	"github.com/jmoiron/sqlx"
)

const (
	subjectTypeUser   = "user"
	subjectTypeGroup  = "group"
	subjectTypeClient = "client"
)

func bumpGlobalAuthzEpochTx(tx *sqlx.Tx) *ErrorResponse {
	registerGlobalAuthzEpochTouch(tx)
	return nil
}

func bumpSubjectAuthzEpochTx(tx *sqlx.Tx, subjectType string, subjectName string) *ErrorResponse {
	subjectType = strings.TrimSpace(subjectType)
	subjectName = strings.ToLower(strings.TrimSpace(subjectName))
	if subjectType == "" || subjectName == "" {
		return nil
	}
	registerSubjectAuthzEpochTouch(tx, subjectType, subjectName)
	return nil
}

func bumpResourceAuthzEpochTx(_ *sqlx.Tx, _ string) *ErrorResponse {
	return nil
}
