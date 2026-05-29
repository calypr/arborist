package arborist

import (
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
)

type accessUserRequest struct {
	ResourcePath string `json:"resource_path"`
	Username     string `json:"username"`
	RoleID       string `json:"role_id"`
}

type accessMutationEntry struct {
	Kind     string `json:"kind"`
	PolicyID string `json:"policy_id,omitempty"`
	RoleID   string `json:"role_id"`
	Reason   string `json:"reason,omitempty"`
}

type accessUserResponse struct {
	ResourcePath string                `json:"resource_path"`
	Username     string                `json:"username"`
	RoleID       string                `json:"role_id"`
	Granted      []accessMutationEntry `json:"granted,omitempty"`
	Removed      []accessMutationEntry `json:"removed,omitempty"`
	NotRemoved   []accessMutationEntry `json:"not_removed,omitempty"`
}

type directUserAccessCandidate struct {
	PolicyID        string `db:"policy_id"`
	ResourcePath    string `db:"resource_path"`
	RoleCount       int    `db:"role_count"`
	ResourceCount   int    `db:"resource_count"`
	IsExactResource bool   `db:"is_exact_resource"`
}

type groupAccessCandidate struct {
	PolicyID     string `db:"policy_id"`
	ResourcePath string `db:"resource_path"`
	GroupName    string `db:"group_name"`
}

func normalizeAccessUserRequest(request accessUserRequest) accessUserRequest {
	return accessUserRequest{
		ResourcePath: cleanResourcePath(request.ResourcePath),
		Username:     strings.ToLower(strings.TrimSpace(request.Username)),
		RoleID:       strings.TrimSpace(request.RoleID),
	}
}

func grantUserAccess(tx *sqlx.Tx, request accessUserRequest, createdBy string) (*accessUserResponse, *ErrorResponse) {
	request = normalizeAccessUserRequest(request)
	if request.ResourcePath == "" || request.Username == "" || request.RoleID == "" {
		return nil, newErrorResponse("resource_path, username, and role_id are required", 400, nil)
	}
	template, resourceID, errResponse := templateForAccessResource(tx, request.ResourcePath)
	if errResponse != nil {
		return nil, errResponse
	}
	if !template.roleIsDelegable(request.RoleID) {
		msg := fmt.Sprintf("role %s is not delegable for template %s", request.RoleID, template.Name)
		return nil, newErrorResponse(msg, 400, nil)
	}
	if errResponse := ensureDelegatedUserBinding(tx, template, resourceID, request.ResourcePath, request.Username, request.RoleID, createdBy); errResponse != nil {
		return nil, errResponse
	}
	return &accessUserResponse{
		ResourcePath: request.ResourcePath,
		Username:     request.Username,
		RoleID:       request.RoleID,
		Granted: []accessMutationEntry{{
			Kind:     "delegated",
			PolicyID: generatedPolicyName("delegated", request.ResourcePath, request.RoleID),
			RoleID:   request.RoleID,
		}},
	}, nil
}

func templateForAccessResource(tx *sqlx.Tx, resourcePath string) (*ownershipTemplate, int64, *ErrorResponse) {
	template, resourceID, errResponse := templateForResource(tx, resourcePath)
	if errResponse == nil {
		return template, resourceID, nil
	}
	resource, err := resourceWithPathTx(tx, resourcePath)
	if err != nil {
		return nil, 0, newErrorResponse(fmt.Sprintf("resource lookup failed: %s", err.Error()), 500, &err)
	}
	if resource == nil {
		return nil, 0, newErrorResponse(fmt.Sprintf("resource does not exist: %s", resourcePath), 404, nil)
	}
	parentPath, ok := parentResourcePath(resourcePath)
	if !ok {
		return nil, 0, errResponse
	}
	template, errResponse = templateForParent(tx, parentPath, "")
	if errResponse != nil {
		return nil, 0, errResponse
	}
	return template, resource.ID, nil
}

func parentResourcePath(resourcePath string) (string, bool) {
	resourcePath = cleanResourcePath(resourcePath)
	lastSlash := strings.LastIndex(resourcePath, "/")
	if lastSlash <= 0 {
		return "", false
	}
	return resourcePath[:lastSlash], true
}

func revokeUserAccess(tx *sqlx.Tx, request accessUserRequest) (*accessUserResponse, *ErrorResponse) {
	request = normalizeAccessUserRequest(request)
	if request.ResourcePath == "" || request.Username == "" || request.RoleID == "" {
		return nil, newErrorResponse("resource_path, username, and role_id are required", 400, nil)
	}

	response := &accessUserResponse{
		ResourcePath: request.ResourcePath,
		Username:     request.Username,
		RoleID:       request.RoleID,
	}

	deletedGenerated, errResponse := deleteGeneratedUserBindingWithCount(tx, request.ResourcePath, request.Username, "delegated", request.RoleID)
	if errResponse != nil {
		return nil, errResponse
	}
	if deletedGenerated > 0 {
		response.Removed = append(response.Removed, accessMutationEntry{
			Kind:     "delegated",
			PolicyID: generatedPolicyName("delegated", request.ResourcePath, request.RoleID),
			RoleID:   request.RoleID,
		})
	}

	directCandidates, errResponse := directUserAccessCandidates(tx, request)
	if errResponse != nil {
		return nil, errResponse
	}
	for _, candidate := range directCandidates {
		if candidate.IsExactResource && candidate.RoleCount == 1 && candidate.ResourceCount == 1 {
			if errResponse := deleteExactDirectUserPolicy(tx, request.Username, candidate.PolicyID); errResponse != nil {
				return nil, errResponse
			}
			response.Removed = append(response.Removed, accessMutationEntry{
				Kind:     "direct",
				PolicyID: candidate.PolicyID,
				RoleID:   request.RoleID,
			})
			continue
		}
		response.NotRemoved = append(response.NotRemoved, accessMutationEntry{
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
		response.NotRemoved = append(response.NotRemoved, accessMutationEntry{
			Kind:     "group",
			PolicyID: candidate.PolicyID,
			RoleID:   request.RoleID,
			Reason:   fmt.Sprintf("group_grant:%s", candidate.GroupName),
		})
	}

	if len(response.Removed) == 0 && len(response.NotRemoved) == 0 {
		response.NotRemoved = append(response.NotRemoved, accessMutationEntry{
			Kind:   "none",
			RoleID: request.RoleID,
			Reason: "grant_not_found",
		})
	}
	return response, nil
}

func directCandidateRejectReason(candidate directUserAccessCandidate) string {
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

func directUserAccessCandidates(tx *sqlx.Tx, request accessUserRequest) ([]directUserAccessCandidate, *ErrorResponse) {
	candidates := []directUserAccessCandidate{}
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
	if err := tx.Select(&candidates, stmt, request.Username, request.RoleID, FormatPathForDb(request.ResourcePath)); err != nil {
		return nil, newErrorResponse(fmt.Sprintf("direct access candidate query failed: %s", err.Error()), 500, &err)
	}
	return candidates, nil
}

func groupAccessCandidatesForUser(tx *sqlx.Tx, request accessUserRequest) ([]groupAccessCandidate, *ErrorResponse) {
	candidates := []groupAccessCandidate{}
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
	if err := tx.Select(&candidates, stmt, request.Username, request.RoleID, FormatPathForDb(request.ResourcePath)); err != nil {
		return nil, newErrorResponse(fmt.Sprintf("group access candidate query failed: %s", err.Error()), 500, &err)
	}
	return candidates, nil
}

func deleteExactDirectUserPolicy(tx *sqlx.Tx, username string, policyID string) *ErrorResponse {
	stmt := `
		DELETE FROM usr_policy
		USING usr, policy
		WHERE usr_policy.usr_id = usr.id
		AND usr_policy.policy_id = policy.id
		AND LOWER(usr.name) = $1
		AND policy.name = $2
	`
	if _, err := tx.Exec(stmt, username, policyID); err != nil {
		return newErrorResponse(fmt.Sprintf("failed to remove direct user access policy: %s", err.Error()), 500, &err)
	}
	return nil
}
