package arborist

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
)

func ensureOwnershipBaseRoles(tx *sqlx.Tx, ownerRole string) *ErrorResponse {
	roleID, errResponse := ensureRole(tx, ownerRole, "Generated owner role")
	if errResponse != nil {
		return errResponse
	}
	permissions := []struct {
		name    string
		service string
		method  string
	}{
		{"owner_read", "*", "read"},
		{"owner_create", "*", "create"},
		{"owner_update", "*", "update"},
		{"owner_write_storage", "*", "write-storage"},
		{"owner_read_storage", "*", "read-storage"},
		{"owner_create_descendant", "arborist", createDescendantMethod},
		{"owner_manage_owners", "arborist", "manage-owners"},
	}
	for _, permission := range permissions {
		stmt := `
			INSERT INTO permission(role_id, name, service, method)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (role_id, name) DO NOTHING
		`
		if _, err := tx.Exec(stmt, roleID, permission.name, permission.service, permission.method); err != nil {
			return newErrorResponse(fmt.Sprintf("failed to ensure owner permission: %s", err.Error()), 500, &err)
		}
	}
	return nil
}

func ensureRole(tx *sqlx.Tx, roleName string, description string) (int64, *ErrorResponse) {
	var roleID int64
	stmt := `
		INSERT INTO role(name, description)
		VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		RETURNING id
	`
	if err := tx.Get(&roleID, stmt, roleName, description); err != nil {
		return 0, newErrorResponse(fmt.Sprintf("failed to ensure role %s: %s", roleName, err.Error()), 500, &err)
	}
	return roleID, nil
}

func ensureOwnerBinding(tx *sqlx.Tx, template *ownershipTemplate, resourceID int64, resourcePath string, username string, createdBy string) *ErrorResponse {
	return ensureGeneratedUserBinding(tx, template, resourceID, resourcePath, username, template.OwnerRole, "owner", true, createdBy)
}

func ensureDelegatedUserBinding(tx *sqlx.Tx, template *ownershipTemplate, resourceID int64, resourcePath string, username string, roleID string, createdBy string) *ErrorResponse {
	return ensureGeneratedUserBinding(tx, template, resourceID, resourcePath, username, roleID, "delegated", false, createdBy)
}

func ensureGeneratedUserBinding(tx *sqlx.Tx, template *ownershipTemplate, resourceID int64, resourcePath string, username string, roleID string, kind string, protected bool, createdBy string) *ErrorResponse {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return newErrorResponse("username is required", 400, nil)
	}
	if errResponse := ensureUser(tx, username); errResponse != nil {
		return errResponse
	}
	policyName, policyID, errResponse := ensureGeneratedPolicy(tx, template, resourceID, resourcePath, roleID, kind, protected, createdBy)
	if errResponse != nil {
		return errResponse
	}
	stmt := `
		INSERT INTO usr_policy(usr_id, policy_id, authz_provider)
		VALUES ((SELECT id FROM usr WHERE name = $1), $2, $3)
		ON CONFLICT (usr_id, policy_id) DO UPDATE SET authz_provider = EXCLUDED.authz_provider
	`
	if _, err := tx.Exec(stmt, username, policyID, sql.NullString{String: ownershipProvider, Valid: true}); err != nil {
		return newErrorResponse(fmt.Sprintf("failed to bind generated policy %s to user %s: %s", policyName, username, err.Error()), 500, &err)
	}
	return upsertBindingMetadata(tx, ownerSubjectType, username, policyID, resourceID, template.Name, kind, protected, createdBy)
}

func ensureProtectedAdminBinding(tx *sqlx.Tx, template *ownershipTemplate, resourceID int64, resourcePath string, groupName string, createdBy string) (string, *ErrorResponse) {
	groupName = strings.TrimSpace(groupName)
	if groupName == "" {
		return "", nil
	}
	var count int
	if err := tx.Get(&count, "SELECT COUNT(*) FROM grp WHERE name = $1", groupName); err != nil {
		return "", newErrorResponse(fmt.Sprintf("admin group lookup failed: %s", err.Error()), 500, &err)
	}
	if count == 0 {
		return "", newErrorResponse(fmt.Sprintf("configured admin group does not exist: %s", groupName), 500, nil)
	}
	policyName, policyID, errResponse := ensureGeneratedPolicy(tx, template, resourceID, resourcePath, template.AdminRole, "admin", true, createdBy)
	if errResponse != nil {
		return "", errResponse
	}
	stmt := `
		INSERT INTO grp_policy(grp_id, policy_id, authz_provider)
		VALUES ((SELECT id FROM grp WHERE name = $1), $2, $3)
		ON CONFLICT (grp_id, policy_id) DO UPDATE SET authz_provider = EXCLUDED.authz_provider
	`
	if _, err := tx.Exec(stmt, groupName, policyID, sql.NullString{String: ownershipProvider, Valid: true}); err != nil {
		return "", newErrorResponse(fmt.Sprintf("failed to bind admin policy %s to group %s: %s", policyName, groupName, err.Error()), 500, &err)
	}
	errResponse = upsertBindingMetadata(tx, "group", groupName, policyID, resourceID, template.Name, "admin", true, createdBy)
	return policyName, errResponse
}

func ensureGeneratedPolicy(tx *sqlx.Tx, template *ownershipTemplate, resourceID int64, resourcePath string, roleID string, kind string, protected bool, createdBy string) (string, int64, *ErrorResponse) {
	policyName := generatedPolicyName(kind, resourcePath, roleID)
	var policyID int64
	stmt := `
		INSERT INTO policy(name, description)
		VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
		RETURNING id
	`
	description := fmt.Sprintf("Generated %s policy for %s", kind, resourcePath)
	if err := tx.Get(&policyID, stmt, policyName, description); err != nil {
		return "", 0, newErrorResponse(fmt.Sprintf("failed to ensure generated policy: %s", err.Error()), 500, &err)
	}
	if _, err := tx.Exec(
		"INSERT INTO policy_resource(policy_id, resource_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		policyID,
		resourceID,
	); err != nil {
		return "", 0, newErrorResponse(fmt.Sprintf("failed to attach generated policy resource: %s", err.Error()), 500, &err)
	}
	if _, err := tx.Exec(
		"INSERT INTO policy_role(policy_id, role_id) VALUES ($1, (SELECT id FROM role WHERE name = $2)) ON CONFLICT DO NOTHING",
		policyID,
		roleID,
	); err != nil {
		return "", 0, newErrorResponse(fmt.Sprintf("failed to attach generated policy role: %s", err.Error()), 500, &err)
	}
	provenance := fmt.Sprintf(`{"source":"arborist-ownership","resource_path":%q,"role_id":%q}`, resourcePath, roleID)
	stmt = `
		INSERT INTO generated_policy_metadata(policy_id, resource_id, template_name, kind, protected, created_by, provenance)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
		ON CONFLICT (policy_id) DO UPDATE SET protected = EXCLUDED.protected
	`
	if _, err := tx.Exec(stmt, policyID, resourceID, template.Name, kind, protected, createdBy, provenance); err != nil {
		return "", 0, newErrorResponse(fmt.Sprintf("failed to write generated policy metadata: %s", err.Error()), 500, &err)
	}
	return policyName, policyID, nil
}

func attachPolicyToResource(tx *sqlx.Tx, policyName string, resourceID int64) *ErrorResponse {
	stmt := `
		INSERT INTO policy_resource(policy_id, resource_id)
		VALUES ((SELECT id FROM policy WHERE name = $1), $2)
		ON CONFLICT DO NOTHING
	`
	if _, err := tx.Exec(stmt, policyName, resourceID); err != nil {
		return newErrorResponse(fmt.Sprintf("failed to attach policy %s to resource: %s", policyName, err.Error()), 500, &err)
	}
	return nil
}

func upsertBindingMetadata(tx *sqlx.Tx, subjectType string, subjectName string, policyID int64, resourceID int64, templateName string, kind string, protected bool, createdBy string) *ErrorResponse {
	provenance := fmt.Sprintf(`{"source":"arborist-ownership","subject_type":%q,"subject_name":%q}`, subjectType, subjectName)
	stmt := `
		INSERT INTO ownership_binding_metadata(subject_type, subject_name, policy_id, resource_id, template_name, kind, protected, created_by, provenance)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
		ON CONFLICT (subject_type, subject_name, policy_id) DO UPDATE SET protected = EXCLUDED.protected
	`
	if _, err := tx.Exec(stmt, subjectType, subjectName, policyID, resourceID, templateName, kind, protected, createdBy, provenance); err != nil {
		return newErrorResponse(fmt.Sprintf("failed to write ownership binding metadata: %s", err.Error()), 500, &err)
	}
	return nil
}

func ensureUser(tx *sqlx.Tx, username string) *ErrorResponse {
	stmt := "INSERT INTO usr(name) VALUES ($1) ON CONFLICT (name) DO NOTHING"
	if _, err := tx.Exec(stmt, username); err != nil {
		return newErrorResponse(fmt.Sprintf("failed to ensure user %s: %s", username, err.Error()), 500, &err)
	}
	return nil
}

func removeOwnerBinding(tx *sqlx.Tx, resourcePath string, username string) *ErrorResponse {
	resourcePath = cleanResourcePath(resourcePath)
	username = strings.ToLower(strings.TrimSpace(username))
	var remainingOwners int
	stmt := `
		SELECT COUNT(*)
		FROM ownership_binding_metadata
		JOIN resource ON ownership_binding_metadata.resource_id = resource.id
		WHERE resource.path = text2ltree($1)
		AND kind = 'owner'
		AND NOT (subject_type = $2 AND LOWER(subject_name) = $3)
	`
	if err := tx.Get(&remainingOwners, stmt, FormatPathForDb(resourcePath), ownerSubjectType, username); err != nil {
		return newErrorResponse(fmt.Sprintf("owner count failed: %s", err.Error()), 500, &err)
	}
	var protectedAdmins int
	stmt = `
		SELECT COUNT(*)
		FROM ownership_binding_metadata
		JOIN resource ON ownership_binding_metadata.resource_id = resource.id
		WHERE resource.path = text2ltree($1)
		AND kind = 'admin'
		AND protected = TRUE
	`
	if err := tx.Get(&protectedAdmins, stmt, FormatPathForDb(resourcePath)); err != nil {
		return newErrorResponse(fmt.Sprintf("admin recovery count failed: %s", err.Error()), 500, &err)
	}
	if remainingOwners == 0 && protectedAdmins == 0 {
		return newErrorResponse("cannot remove the last owner without a protected admin recovery binding", 400, nil)
	}
	return deleteGeneratedUserBinding(tx, resourcePath, username, "owner", "")
}

func removeDelegatedUserBinding(tx *sqlx.Tx, resourcePath string, username string, roleID string) *ErrorResponse {
	return deleteGeneratedUserBinding(tx, cleanResourcePath(resourcePath), strings.ToLower(strings.TrimSpace(username)), "delegated", roleID)
}

func deleteGeneratedUserBinding(tx *sqlx.Tx, resourcePath string, username string, kind string, roleID string) *ErrorResponse {
	_, errResponse := deleteGeneratedUserBindingWithCount(tx, resourcePath, username, kind, roleID)
	return errResponse
}

func deleteGeneratedUserBindingWithCount(tx *sqlx.Tx, resourcePath string, username string, kind string, roleID string) (int64, *ErrorResponse) {
	policyNamePredicate := ""
	args := []interface{}{FormatPathForDb(resourcePath), ownerSubjectType, username, kind}
	if roleID != "" {
		policyNamePredicate = "AND policy.name = $5"
		args = append(args, generatedPolicyName(kind, resourcePath, roleID))
	}
	stmt := fmt.Sprintf(`
		DELETE FROM usr_policy
		USING usr, policy, ownership_binding_metadata, resource
		WHERE usr_policy.usr_id = usr.id
		AND usr_policy.policy_id = policy.id
		AND ownership_binding_metadata.policy_id = policy.id
		AND ownership_binding_metadata.resource_id = resource.id
		AND resource.path = text2ltree($1)
		AND LOWER(usr.name) = $3
		AND ownership_binding_metadata.subject_type = $2
		AND LOWER(ownership_binding_metadata.subject_name) = $3
		AND ownership_binding_metadata.kind = $4
		%s
	`, policyNamePredicate)
	if _, err := tx.Exec(stmt, args...); err != nil {
		return 0, newErrorResponse(fmt.Sprintf("failed to remove generated user binding: %s", err.Error()), 500, &err)
	}
	stmt = fmt.Sprintf(`
		DELETE FROM ownership_binding_metadata
		USING policy, resource
		WHERE ownership_binding_metadata.policy_id = policy.id
		AND ownership_binding_metadata.resource_id = resource.id
		AND resource.path = text2ltree($1)
		AND ownership_binding_metadata.subject_type = $2
		AND LOWER(ownership_binding_metadata.subject_name) = $3
		AND ownership_binding_metadata.kind = $4
		%s
	`, policyNamePredicate)
	result, err := tx.Exec(stmt, args...)
	if err != nil {
		return 0, newErrorResponse(fmt.Sprintf("failed to remove ownership binding metadata: %s", err.Error()), 500, &err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, newErrorResponse(fmt.Sprintf("failed to inspect ownership binding removal: %s", err.Error()), 500, &err)
	}
	return rowsAffected, nil
}

func generatedPolicyName(kind string, resourcePath string, roleID string) string {
	resourcePart := strings.Trim(FormatPathForDb(resourcePath), ".")
	return fmt.Sprintf("generated.%s.%s.%s", kind, resourcePart, roleID)
}
