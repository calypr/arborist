package ownership

import (
	"database/sql"
	"fmt"
	"strings"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/jmoiron/sqlx"
)

func ensureOwnershipBaseRoles(tx *sqlx.Tx, ownerRole string) *coreauthz.ErrorResponse {
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
		{"owner_delete", "*", "delete"},
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
			return coreauthz.NewErrorResponse(fmt.Sprintf("failed to ensure owner permission: %s", err.Error()), 500, &err)
		}
	}
	memberRoleID, errResponse := ensureRole(tx, orgMemberRole, "Generated organization member role")
	if errResponse != nil {
		return errResponse
	}
	stmt := `
		INSERT INTO permission(role_id, name, service, method)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (role_id, name) DO NOTHING
	`
	if _, err := tx.Exec(stmt, memberRoleID, "org_member_create_descendant", "arborist", createDescendantMethod); err != nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("failed to ensure org member permission: %s", err.Error()), 500, &err)
	}
	return nil
}

func ensureRole(tx *sqlx.Tx, roleName string, description string) (int64, *coreauthz.ErrorResponse) {
	var roleID int64
	stmt := `
		INSERT INTO role(name, description)
		VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		RETURNING id
	`
	if err := tx.Get(&roleID, stmt, roleName, description); err != nil {
		return 0, coreauthz.NewErrorResponse(fmt.Sprintf("failed to ensure role %s: %s", roleName, err.Error()), 500, &err)
	}
	return roleID, nil
}

func ensureOwnerBinding(tx *sqlx.Tx, template *OwnershipTemplate, resourceID int64, resourcePath string, username string, createdBy string) *coreauthz.ErrorResponse {
	target := NewManagedOwnershipTarget(template, resourceID, resourcePath)
	if errResponse := ensureGeneratedUserBinding(tx, target, username, template.OwnerRole, "owner", false, createdBy); errResponse != nil {
		return errResponse
	}
	return attachGeneratedPolicyToChildContainer(tx, target, "owner", template.OwnerRole)
}

func ensureOwnerBindingForTarget(tx *sqlx.Tx, target *OwnershipTarget, username string, createdBy string) *coreauthz.ErrorResponse {
	if errResponse := ensureGeneratedUserBinding(tx, target, username, target.Template.OwnerRole, "owner", false, createdBy); errResponse != nil {
		return errResponse
	}
	return attachGeneratedPolicyToChildContainer(tx, target, "owner", target.Template.OwnerRole)
}

func attachGeneratedPolicyToChildContainer(tx *sqlx.Tx, target *OwnershipTarget, kind string, roleID string) *coreauthz.ErrorResponse {
	if !target.Template.ChildContainerName.Valid {
		return nil
	}
	if target.Kind == ownershipTargetChildContainerKind {
		return nil
	}
	containerPath := coreauthz.CleanResourcePath(target.ResourcePath + "/" + target.Template.ChildContainerName.String)
	container, err := resourceWithPathTx(tx, containerPath)
	if err != nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("container lookup failed: %s", err.Error()), 500, &err)
	}
	if container == nil {
		return nil
	}
	return attachPolicyToResource(tx, generatedPolicyName(kind, target.PolicyPath, roleID), container.ID)
}

func ensureGeneratedUserBinding(tx *sqlx.Tx, target *OwnershipTarget, username string, roleID string, kind string, protected bool, createdBy string) *coreauthz.ErrorResponse {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return coreauthz.NewErrorResponse("username is required", 400, nil)
	}
	if errResponse := ensureUser(tx, username); errResponse != nil {
		return errResponse
	}
	policyName, policyID, errResponse := ensureGeneratedPolicy(tx, target, roleID, kind, protected, createdBy)
	if errResponse != nil {
		return errResponse
	}
	stmt := `
		INSERT INTO usr_policy(usr_id, policy_id, authz_provider)
		VALUES ((SELECT id FROM usr WHERE name = $1), $2, $3)
		ON CONFLICT (usr_id, policy_id) DO UPDATE SET authz_provider = EXCLUDED.authz_provider
	`
	if _, err := tx.Exec(stmt, username, policyID, sql.NullString{String: ownershipProvider, Valid: true}); err != nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("failed to bind generated policy %s to user %s: %s", policyName, username, err.Error()), 500, &err)
	}
	return upsertBindingMetadata(tx, ownerSubjectType, username, policyID, target.ResourceID, target.Template.Name, kind, protected, createdBy)
}

func ensureProtectedAdminBinding(tx *sqlx.Tx, template *OwnershipTemplate, resourceID int64, resourcePath string, groupName string, createdBy string) (string, *coreauthz.ErrorResponse) {
	target := NewManagedOwnershipTarget(template, resourceID, resourcePath)
	return ensureProtectedAdminBindingForTarget(tx, target, groupName, createdBy)
}

func ensureProtectedAdminBindingForTarget(tx *sqlx.Tx, target *OwnershipTarget, groupName string, createdBy string) (string, *coreauthz.ErrorResponse) {
	groupName = strings.TrimSpace(groupName)
	if groupName == "" {
		return "", nil
	}
	var count int
	if err := tx.Get(&count, "SELECT COUNT(*) FROM grp WHERE name = $1", groupName); err != nil {
		return "", coreauthz.NewErrorResponse(fmt.Sprintf("admin group lookup failed: %s", err.Error()), 500, &err)
	}
	if count == 0 {
		return "", coreauthz.NewErrorResponse(fmt.Sprintf("configured admin group does not exist: %s", groupName), 500, nil)
	}
	policyName, policyID, errResponse := ensureGeneratedPolicy(tx, target, target.Template.AdminRole, "admin", true, createdBy)
	if errResponse != nil {
		return "", errResponse
	}
	stmt := `
		INSERT INTO grp_policy(grp_id, policy_id, authz_provider)
		VALUES ((SELECT id FROM grp WHERE name = $1), $2, $3)
		ON CONFLICT (grp_id, policy_id) DO UPDATE SET authz_provider = EXCLUDED.authz_provider
	`
	if _, err := tx.Exec(stmt, groupName, policyID, sql.NullString{String: ownershipProvider, Valid: true}); err != nil {
		return "", coreauthz.NewErrorResponse(fmt.Sprintf("failed to bind admin policy %s to group %s: %s", policyName, groupName, err.Error()), 500, &err)
	}
	errResponse = upsertBindingMetadata(tx, "group", groupName, policyID, target.ResourceID, target.Template.Name, "admin", true, createdBy)
	return policyName, errResponse
}

func ensureGeneratedPolicy(tx *sqlx.Tx, target *OwnershipTarget, roleID string, kind string, protected bool, createdBy string) (string, int64, *coreauthz.ErrorResponse) {
	policyName := generatedPolicyName(kind, target.PolicyPath, roleID)
	roleDBID, errResponse := roleIDByName(tx, roleID)
	if errResponse != nil {
		return "", 0, errResponse
	}
	var policyID int64
	stmt := `
		INSERT INTO policy(name, description)
		VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
		RETURNING id
	`
	description := fmt.Sprintf("Generated %s policy for %s", kind, target.PolicyPath)
	if err := tx.Get(&policyID, stmt, policyName, description); err != nil {
		return "", 0, coreauthz.NewErrorResponse(fmt.Sprintf("failed to ensure generated policy: %s", err.Error()), 500, &err)
	}
	if _, err := tx.Exec(
		"INSERT INTO policy_resource(policy_id, resource_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		policyID,
		target.ResourceID,
	); err != nil {
		return "", 0, coreauthz.NewErrorResponse(fmt.Sprintf("failed to attach generated policy resource: %s", err.Error()), 500, &err)
	}
	if _, err := tx.Exec(
		"INSERT INTO policy_role(policy_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		policyID,
		roleDBID,
	); err != nil {
		return "", 0, coreauthz.NewErrorResponse(fmt.Sprintf("failed to attach generated policy role: %s", err.Error()), 500, &err)
	}
	provenance := fmt.Sprintf(`{"source":"arborist-ownership","resource_path":%q,"anchor_path":%q,"target_kind":%q,"role_id":%q}`, target.PolicyPath, target.AnchorPath, target.Kind, roleID)
	stmt = `
		INSERT INTO generated_policy_metadata(policy_id, resource_id, template_name, kind, protected, created_by, provenance)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
		ON CONFLICT (policy_id) DO UPDATE SET protected = EXCLUDED.protected
	`
	if _, err := tx.Exec(stmt, policyID, target.ResourceID, target.Template.Name, kind, protected, createdBy, provenance); err != nil {
		return "", 0, coreauthz.NewErrorResponse(fmt.Sprintf("failed to write generated policy metadata: %s", err.Error()), 500, &err)
	}
	return policyName, policyID, nil
}

func roleIDByName(tx *sqlx.Tx, roleName string) (int64, *coreauthz.ErrorResponse) {
	var roleID int64
	err := tx.Get(&roleID, "SELECT id FROM role WHERE name = $1", roleName)
	if err == nil {
		return roleID, nil
	}
	if err == sql.ErrNoRows {
		return 0, coreauthz.NewErrorResponse(fmt.Sprintf("configured ownership role does not exist: %s", roleName), 500, &err)
	}
	return 0, coreauthz.NewErrorResponse(fmt.Sprintf("role lookup failed for %s: %s", roleName, err.Error()), 500, &err)
}

func attachPolicyToResource(tx *sqlx.Tx, policyName string, resourceID int64) *coreauthz.ErrorResponse {
	stmt := `
		INSERT INTO policy_resource(policy_id, resource_id)
		VALUES ((SELECT id FROM policy WHERE name = $1), $2)
		ON CONFLICT DO NOTHING
	`
	if _, err := tx.Exec(stmt, policyName, resourceID); err != nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("failed to attach policy %s to resource: %s", policyName, err.Error()), 500, &err)
	}
	return nil
}

func upsertBindingMetadata(tx *sqlx.Tx, subjectType string, subjectName string, policyID int64, resourceID int64, templateName string, kind string, protected bool, createdBy string) *coreauthz.ErrorResponse {
	provenance := fmt.Sprintf(`{"source":"arborist-ownership","subject_type":%q,"subject_name":%q}`, subjectType, subjectName)
	stmt := `
		INSERT INTO ownership_binding_metadata(subject_type, subject_name, policy_id, resource_id, template_name, kind, protected, created_by, provenance)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
		ON CONFLICT (subject_type, subject_name, policy_id) DO UPDATE SET protected = EXCLUDED.protected
	`
	if _, err := tx.Exec(stmt, subjectType, subjectName, policyID, resourceID, templateName, kind, protected, createdBy, provenance); err != nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("failed to write ownership binding metadata: %s", err.Error()), 500, &err)
	}
	return nil
}

func ensureUser(tx *sqlx.Tx, username string) *coreauthz.ErrorResponse {
	stmt := "INSERT INTO usr(name) VALUES ($1) ON CONFLICT (name) DO NOTHING"
	if _, err := tx.Exec(stmt, username); err != nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("failed to ensure user %s: %s", username, err.Error()), 500, &err)
	}
	return nil
}

func removeOwnerBinding(tx *sqlx.Tx, resourcePath string, username string) *coreauthz.ErrorResponse {
	resourcePath = coreauthz.CleanResourcePath(resourcePath)
	username = strings.ToLower(strings.TrimSpace(username))
	return deleteGeneratedUserBinding(tx, resourcePath, username, "owner", "")
}

func deleteGeneratedUserBinding(tx *sqlx.Tx, resourcePath string, username string, kind string, roleID string) *coreauthz.ErrorResponse {
	_, errResponse := deleteGeneratedUserBindingWithCount(tx, resourcePath, username, kind, roleID)
	return errResponse
}

func deleteGeneratedUserBindingWithCount(tx *sqlx.Tx, resourcePath string, username string, kind string, roleID string) (int64, *coreauthz.ErrorResponse) {
	policyNamePredicate := ""
	args := []interface{}{coreauthz.FormatPathForDb(resourcePath), ownerSubjectType, username, kind}
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
		return 0, coreauthz.NewErrorResponse(fmt.Sprintf("failed to remove generated user binding: %s", err.Error()), 500, &err)
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
		return 0, coreauthz.NewErrorResponse(fmt.Sprintf("failed to remove ownership binding metadata: %s", err.Error()), 500, &err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, coreauthz.NewErrorResponse(fmt.Sprintf("failed to inspect ownership binding removal: %s", err.Error()), 500, &err)
	}
	return rowsAffected, nil
}

func generatedPolicyName(kind string, resourcePath string, roleID string) string {
	resourcePart := strings.Trim(coreauthz.FormatPathForDb(resourcePath), ".")
	return fmt.Sprintf("generated.%s.%s.%s", kind, resourcePart, roleID)
}
