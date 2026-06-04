package access

import (
	"database/sql"
	"fmt"
	"strings"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/calypr/arborist/internal/ownership"
	"github.com/jmoiron/sqlx"
)

type AccessUserRequest struct {
	ResourcePath string `json:"resource_path"`
	Username     string `json:"username"`
	RoleID       string `json:"role_id"`
}

type AccessMutationEntry struct {
	Kind     string `json:"kind"`
	PolicyID string `json:"policy_id,omitempty"`
	RoleID   string `json:"role_id"`
	Reason   string `json:"reason,omitempty"`
}

type AccessUserResponse struct {
	ResourcePath string                `json:"resource_path"`
	Username     string                `json:"username"`
	RoleID       string                `json:"role_id"`
	Granted      []AccessMutationEntry `json:"granted,omitempty"`
	Removed      []AccessMutationEntry `json:"removed,omitempty"`
	NotRemoved   []AccessMutationEntry `json:"not_removed,omitempty"`
}

type DirectUserAccessCandidate struct {
	PolicyID        string `db:"policy_id"`
	ResourcePath    string `db:"resource_path"`
	RoleCount       int    `db:"role_count"`
	ResourceCount   int    `db:"resource_count"`
	IsExactResource bool   `db:"is_exact_resource"`
}

type GroupAccessCandidate struct {
	PolicyID     string `db:"policy_id"`
	ResourcePath string `db:"resource_path"`
	GroupName    string `db:"group_name"`
}

func NormalizeAccessUserRequest(request AccessUserRequest) AccessUserRequest {
	return AccessUserRequest{
		ResourcePath: coreauthz.CleanResourcePath(request.ResourcePath),
		Username:     strings.ToLower(strings.TrimSpace(request.Username)),
		RoleID:       strings.TrimSpace(request.RoleID),
	}
}

func GrantUserAccess(tx *sqlx.Tx, request AccessUserRequest, createdBy string, authzProvider sql.NullString) (*AccessUserResponse, *coreauthz.ErrorResponse) {
	request = NormalizeAccessUserRequest(request)
	if request.ResourcePath == "" || request.Username == "" || request.RoleID == "" {
		return nil, coreauthz.NewErrorResponse("resource_path, username, and role_id are required", 400, nil)
	}
	target, errResponse := resolveAccessTarget(tx, request.ResourcePath)
	if errResponse != nil {
		return nil, errResponse
	}
	if !target.Template.RoleIsGrantable(request.RoleID) {
		msg := fmt.Sprintf("role %s is not grantable for template %s", request.RoleID, target.Template.Name)
		return nil, coreauthz.NewErrorResponse(msg, 400, nil)
	}
	if errResponse := ensureDirectUserBindingForTarget(tx, target, request.Username, request.RoleID, createdBy, authzProvider); errResponse != nil {
		return nil, errResponse
	}
	return &AccessUserResponse{
		ResourcePath: request.ResourcePath,
		Username:     request.Username,
		RoleID:       request.RoleID,
		Granted: []AccessMutationEntry{{
			Kind:     "direct",
			PolicyID: directAccessPolicyName(request.ResourcePath, request.RoleID),
			RoleID:   request.RoleID,
		}},
	}, nil
}

func resolveAccessTarget(tx *sqlx.Tx, resourcePath string) (*ownership.OwnershipTarget, *coreauthz.ErrorResponse) {
	target, errResponse := ownership.ResolveOwnershipTarget(tx, resourcePath)
	if errResponse == nil {
		return target, nil
	}
	resource, err := ownership.ResourceWithPathTx(tx, resourcePath)
	if err != nil {
		return nil, coreauthz.NewErrorResponse(fmt.Sprintf("resource lookup failed: %s", err.Error()), 500, &err)
	}
	if resource == nil {
		return nil, coreauthz.NewErrorResponse(fmt.Sprintf("resource does not exist: %s", resourcePath), 404, nil)
	}
	parentPath, ok := parentResourcePath(resourcePath)
	if !ok {
		return nil, errResponse
	}
	template, errResponse := ownership.TemplateForParent(tx, parentPath, "")
	if errResponse != nil {
		return nil, errResponse
	}
	return ownership.NewManagedOwnershipTarget(template, resource.ID, resourcePath), nil
}

func parentResourcePath(resourcePath string) (string, bool) {
	resourcePath = coreauthz.CleanResourcePath(resourcePath)
	lastSlash := strings.LastIndex(resourcePath, "/")
	if lastSlash <= 0 {
		return "", false
	}
	return resourcePath[:lastSlash], true
}

func RevokeUserAccess(tx *sqlx.Tx, request AccessUserRequest, authzProvider sql.NullString) (*AccessUserResponse, *coreauthz.ErrorResponse) {
	request = NormalizeAccessUserRequest(request)
	if request.ResourcePath == "" || request.Username == "" || request.RoleID == "" {
		return nil, coreauthz.NewErrorResponse("resource_path, username, and role_id are required", 400, nil)
	}

	response := &AccessUserResponse{
		ResourcePath: request.ResourcePath,
		Username:     request.Username,
		RoleID:       request.RoleID,
	}

	directCandidates, errResponse := directUserAccessCandidates(tx, request)
	if errResponse != nil {
		return nil, errResponse
	}
	for _, candidate := range directCandidates {
		if candidate.IsExactResource && candidate.RoleCount == 1 && candidate.ResourceCount == 1 {
			if errResponse := deleteExactDirectUserPolicy(tx, request.Username, candidate.PolicyID, authzProvider); errResponse != nil {
				return nil, errResponse
			}
			response.Removed = append(response.Removed, AccessMutationEntry{
				Kind:     "direct",
				PolicyID: candidate.PolicyID,
				RoleID:   request.RoleID,
			})
			continue
		}
		response.NotRemoved = append(response.NotRemoved, AccessMutationEntry{
			Kind:     "direct",
			PolicyID: candidate.PolicyID,
			RoleID:   request.RoleID,
			Reason:   directCandidateRejectReason(candidate),
		})
	}

	groupCandidates, errResponse := groupAccessCandidatesForUser(tx, request)
	if errResponse != nil {
		return nil, errResponse
	}
	for _, candidate := range groupCandidates {
		response.NotRemoved = append(response.NotRemoved, AccessMutationEntry{
			Kind:     "group",
			PolicyID: candidate.PolicyID,
			RoleID:   request.RoleID,
			Reason:   fmt.Sprintf("group_grant:%s", candidate.GroupName),
		})
	}

	if len(response.Removed) == 0 && len(response.NotRemoved) == 0 {
		response.NotRemoved = append(response.NotRemoved, AccessMutationEntry{
			Kind:   "none",
			RoleID: request.RoleID,
			Reason: "grant_not_found",
		})
	}
	return response, nil
}

func ensureDirectUserBindingForTarget(tx *sqlx.Tx, target *ownership.OwnershipTarget, username string, roleID string, createdBy string, authzProvider sql.NullString) *coreauthz.ErrorResponse {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return coreauthz.NewErrorResponse("username is required", 400, nil)
	}
	if errResponse := ownership.EnsureUser(tx, username); errResponse != nil {
		return errResponse
	}
	policyName, policyID, errResponse := ensureDirectAccessPolicy(tx, target, roleID, createdBy)
	if errResponse != nil {
		return errResponse
	}
	stmt := `
		INSERT INTO usr_policy(usr_id, policy_id, authz_provider)
		VALUES ((SELECT id FROM usr WHERE name = $1), $2, $3)
		ON CONFLICT (usr_id, policy_id) DO UPDATE SET authz_provider = EXCLUDED.authz_provider
	`
	if _, err := tx.Exec(stmt, username, policyID, authzProvider); err != nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("failed to bind direct policy %s to user %s: %s", policyName, username, err.Error()), 500, &err)
	}
	return nil
}

func ensureDirectAccessPolicy(tx *sqlx.Tx, target *ownership.OwnershipTarget, roleID string, createdBy string) (string, int64, *coreauthz.ErrorResponse) {
	policyName := directAccessPolicyName(target.PolicyPath, roleID)
	roleDBID, errResponse := ownership.RoleIDByName(tx, roleID)
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
	description := fmt.Sprintf("Direct access policy for %s", target.PolicyPath)
	if err := tx.Get(&policyID, stmt, policyName, description); err != nil {
		return "", 0, coreauthz.NewErrorResponse(fmt.Sprintf("failed to ensure direct access policy: %s", err.Error()), 500, &err)
	}
	if _, err := tx.Exec(
		"INSERT INTO policy_resource(policy_id, resource_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		policyID,
		target.ResourceID,
	); err != nil {
		return "", 0, coreauthz.NewErrorResponse(fmt.Sprintf("failed to attach direct access policy resource: %s", err.Error()), 500, &err)
	}
	if _, err := tx.Exec(
		"INSERT INTO policy_role(policy_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		policyID,
		roleDBID,
	); err != nil {
		return "", 0, coreauthz.NewErrorResponse(fmt.Sprintf("failed to attach direct access policy role: %s", err.Error()), 500, &err)
	}
	return policyName, policyID, nil
}

func directCandidateRejectReason(candidate DirectUserAccessCandidate) string {
	if !candidate.IsExactResource {
		return "inherited_from_ancestor"
	}
	if candidate.RoleCount > 1 && candidate.ResourceCount > 1 {
		return "broad_policy_multiple_roles_and_resources"
	}
	if candidate.RoleCount > 1 {
		return "broad_policy_multiple_roles"
	}
	if candidate.ResourceCount > 1 {
		return "broad_policy_multiple_resources"
	}
	return "not_exact_direct_grant"
}

func directUserAccessCandidates(tx *sqlx.Tx, request AccessUserRequest) ([]DirectUserAccessCandidate, *coreauthz.ErrorResponse) {
	candidates := []DirectUserAccessCandidate{}
	stmt := `
		SELECT DISTINCT
			policy.name AS policy_id,
			ltree2text(policy_root.path) AS resource_path,
			(SELECT COUNT(*) FROM policy_role WHERE policy_role.policy_id = policy.id) AS role_count,
			(SELECT COUNT(*) FROM policy_resource WHERE policy_resource.policy_id = policy.id) AS resource_count,
			(policy_root.path = text2ltree($3)) AS is_exact_resource
		FROM usr_policy
		JOIN usr ON usr_policy.usr_id = usr.id
		JOIN policy ON usr_policy.policy_id = policy.id
		JOIN policy_role requested_policy_role ON requested_policy_role.policy_id = policy.id
		JOIN role ON requested_policy_role.role_id = role.id
		JOIN policy_resource ON policy_resource.policy_id = policy.id
		JOIN resource AS policy_root ON policy_resource.resource_id = policy_root.id
		LEFT JOIN generated_policy_metadata ON generated_policy_metadata.policy_id = policy.id
		WHERE LOWER(usr.name) = $1
		AND role.name = $2
		AND text2ltree($3) <@ policy_root.path
		AND generated_policy_metadata.policy_id IS NULL
		AND (usr_policy.expires_at IS NULL OR NOW() < usr_policy.expires_at)
	`
	if err := tx.Select(&candidates, stmt, request.Username, request.RoleID, coreauthz.FormatPathForDb(request.ResourcePath)); err != nil {
		return nil, coreauthz.NewErrorResponse(fmt.Sprintf("direct access candidate query failed: %s", err.Error()), 500, &err)
	}
	return candidates, nil
}

func groupAccessCandidatesForUser(tx *sqlx.Tx, request AccessUserRequest) ([]GroupAccessCandidate, *coreauthz.ErrorResponse) {
	candidates := []GroupAccessCandidate{}
	stmt := `
		SELECT DISTINCT
			policy.name AS policy_id,
			ltree2text(policy_root.path) AS resource_path,
			grp.name AS group_name
		FROM usr
		JOIN usr_grp ON usr_grp.usr_id = usr.id
		JOIN grp ON grp.id = usr_grp.grp_id
		JOIN grp_policy ON grp_policy.grp_id = grp.id
		JOIN policy ON grp_policy.policy_id = policy.id
		JOIN policy_role requested_policy_role ON requested_policy_role.policy_id = policy.id
		JOIN role ON requested_policy_role.role_id = role.id
		JOIN policy_resource ON policy_resource.policy_id = policy.id
		JOIN resource AS policy_root ON policy_resource.resource_id = policy_root.id
		LEFT JOIN generated_policy_metadata ON generated_policy_metadata.policy_id = policy.id
		WHERE LOWER(usr.name) = $1
		AND role.name = $2
		AND text2ltree($3) <@ policy_root.path
		AND generated_policy_metadata.policy_id IS NULL
		AND (usr_grp.expires_at IS NULL OR NOW() < usr_grp.expires_at)
	`
	if err := tx.Select(&candidates, stmt, request.Username, request.RoleID, coreauthz.FormatPathForDb(request.ResourcePath)); err != nil {
		return nil, coreauthz.NewErrorResponse(fmt.Sprintf("group access candidate query failed: %s", err.Error()), 500, &err)
	}
	return candidates, nil
}

func deleteExactDirectUserPolicy(tx *sqlx.Tx, username string, policyID string, authzProvider sql.NullString) *coreauthz.ErrorResponse {
	stmt := `
		DELETE FROM usr_policy
		USING usr, policy
		WHERE usr_policy.usr_id = usr.id
		AND usr_policy.policy_id = policy.id
		AND LOWER(usr.name) = $1
		AND policy.name = $2
	`
	if _, err := tx.Exec(stmt, username, policyID); err != nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("failed to remove direct user access policy: %s", err.Error()), 500, &err)
	}
	return nil
}

func directAccessPolicyName(resourcePath string, roleID string) string {
	resourcePart := strings.Trim(coreauthz.FormatPathForDb(resourcePath), ".")
	return fmt.Sprintf("direct.%s.%s", resourcePart, roleID)
}
