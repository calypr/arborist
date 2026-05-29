package arborist

import (
	"fmt"
	"net/http"
	"strings"
)

func (server *Server) usernameFromBearer(r *http.Request) (string, *ErrorResponse) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", newErrorResponse("Authorization header is required", http.StatusUnauthorized, nil)
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer"))
	info, err := server.decodeToken(token, nil)
	if err != nil {
		return "", newErrorResponse(fmt.Sprintf("invalid authorization token: %s", err.Error()), http.StatusUnauthorized, &err)
	}
	if info.username == "" {
		return "", newErrorResponse("authorization token does not identify a user", http.StatusUnauthorized, nil)
	}
	return strings.ToLower(info.username), nil
}

func (server *Server) authorizeCreateDescendant(username string, parentPath string) *ErrorResponse {
	var authorized bool
	stmt := `
		SELECT EXISTS (
			SELECT 1
			FROM (
				SELECT usr_policy.policy_id FROM usr
				INNER JOIN usr_policy ON usr_policy.usr_id = usr.id
				WHERE LOWER(usr.name) = $1 AND (usr_policy.expires_at IS NULL OR NOW() < usr_policy.expires_at)
				UNION
				SELECT grp_policy.policy_id FROM usr
				INNER JOIN usr_grp ON usr_grp.usr_id = usr.id
				INNER JOIN grp_policy ON grp_policy.grp_id = usr_grp.grp_id
				WHERE LOWER(usr.name) = $1 AND (usr_grp.expires_at IS NULL OR NOW() < usr_grp.expires_at)
				UNION
				SELECT grp_policy.policy_id FROM grp
				INNER JOIN grp_policy ON grp_policy.grp_id = grp.id
				WHERE grp.name IN ($5, $6)
			) AS policies
			JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
			JOIN resource ON resource.id = policy_resource.resource_id
			WHERE resource.path = text2ltree($2)
			AND EXISTS (
				SELECT 1 FROM policy_role
				JOIN permission ON permission.role_id = policy_role.role_id
				WHERE policy_role.policy_id = policies.policy_id
				AND (permission.service = $3 OR permission.service = '*')
				AND (permission.method = $4 OR permission.method = '*')
			)
		)
	`
	err := server.db.Get(
		&authorized,
		stmt,
		strings.ToLower(username),
		FormatPathForDb(parentPath),
		"arborist",
		createDescendantMethod,
		AnonymousGroup,
		LoggedInGroup,
	)
	if err != nil {
		return newErrorResponse(fmt.Sprintf("create-descendant authorization failed: %s", err.Error()), 500, &err)
	}
	if !authorized {
		return newErrorResponse(fmt.Sprintf("user is not allowed to create descendants under %s", parentPath), http.StatusForbidden, nil)
	}
	return nil
}

func (server *Server) requireOwnershipControl(username string, resourcePath string) *ErrorResponse {
	resourcePath = cleanResourcePath(resourcePath)
	var count int
	stmt := `
		SELECT COUNT(*)
		FROM ownership_binding_metadata
		JOIN resource ON ownership_binding_metadata.resource_id = resource.id
		WHERE subject_type = $1
		AND LOWER(subject_name) = $2
		AND kind = 'owner'
		AND resource.path = text2ltree($3)
	`
	if err := server.db.Get(&count, stmt, ownerSubjectType, strings.ToLower(username), FormatPathForDb(resourcePath)); err != nil {
		return newErrorResponse(fmt.Sprintf("owner lookup failed: %s", err.Error()), 500, &err)
	}
	if count > 0 {
		return nil
	}
	request := &AuthRequest{
		Username: username,
		Resource: resourcePath,
		Service:  "arborist",
		Method:   "manage-owners",
		stmts:    server.stmts,
	}
	auth, err := authorizeUser(request)
	if err != nil {
		return newErrorResponse(fmt.Sprintf("ownership authorization failed: %s", err.Error()), 500, &err)
	}
	if !auth.Auth {
		return newErrorResponse(fmt.Sprintf("user is not allowed to manage ownership for %s", resourcePath), http.StatusForbidden, nil)
	}
	return nil
}
