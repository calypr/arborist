package protection

import (
	"database/sql"
	"fmt"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/jmoiron/sqlx"
)

func GeneratedPolicyIsProtected(tx *sqlx.Tx, policyName string) (bool, *coreauthz.ErrorResponse) {
	var protected bool
	stmt := `
		SELECT protected
		FROM generated_policy_metadata
		JOIN policy ON generated_policy_metadata.policy_id = policy.id
		WHERE policy.name = $1
	`
	err := tx.Get(&protected, stmt, policyName)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, coreauthz.NewErrorResponse(fmt.Sprintf("generated policy metadata lookup failed: %s", err.Error()), 500, &err)
	}
	return protected, nil
}

func ResourceHasProtectedOwnership(tx *sqlx.Tx, resourcePath string) (bool, *coreauthz.ErrorResponse) {
	var count int
	stmt := `
		SELECT COUNT(*)
		FROM generated_policy_metadata
		JOIN policy_resource ON generated_policy_metadata.policy_id = policy_resource.policy_id
		JOIN resource ON policy_resource.resource_id = resource.id
		WHERE resource.path = text2ltree($1)
		AND generated_policy_metadata.protected = TRUE
	`
	if err := tx.Get(&count, stmt, coreauthz.FormatPathForDb(resourcePath)); err != nil {
		return false, coreauthz.NewErrorResponse(fmt.Sprintf("resource ownership metadata lookup failed: %s", err.Error()), 500, &err)
	}
	return count > 0, nil
}
