package arborist

import (
	"fmt"

	"github.com/jmoiron/sqlx"
)

func deleteOwnershipResource(tx *sqlx.Tx, resourcePath string) *ErrorResponse {
	resourcePath = cleanResourcePath(resourcePath)
	if resourcePath == "" || resourcePath == "/" {
		return newErrorResponse("resource_path is required", 400, nil)
	}

	stmt := `
		DELETE FROM policy
		WHERE id IN (
			SELECT generated_policy_metadata.policy_id
			FROM generated_policy_metadata
			JOIN policy_resource ON generated_policy_metadata.policy_id = policy_resource.policy_id
			JOIN resource ON policy_resource.resource_id = resource.id
			WHERE resource.path <@ text2ltree($1)
		)
	`
	if _, err := tx.Exec(stmt, FormatPathForDb(resourcePath)); err != nil {
		return newErrorResponse(fmt.Sprintf("failed to delete generated ownership policies: %s", err.Error()), 500, &err)
	}

	resource := ResourceIn{Path: resourcePath}
	return resource.deleteInDb(tx)
}
