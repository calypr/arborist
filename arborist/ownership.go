package arborist

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

const (
	createDescendantMethod = "create-descendant"
	ownershipProvider      = "arborist-ownership"
	ownerSubjectType       = "user"
)

type ownershipTemplate struct {
	Name               string         `db:"name"`
	ParentPathPattern  string         `db:"parent_path_pattern"`
	ChildKind          string         `db:"child_kind"`
	ChildContainerName sql.NullString `db:"child_container_name"`
	OwnerRole          string         `db:"owner_role"`
	AdminRole          string         `db:"admin_role"`
	DefaultAdminGroups pq.StringArray `db:"default_admin_groups"`
	DelegableRoles     pq.StringArray `db:"delegable_roles"`
}

type descendantCreateRequest struct {
	ParentPath  string  `json:"parent_path"`
	Name        string  `json:"name"`
	Template    string  `json:"template,omitempty"`
	Description *string `json:"description,omitempty"`
}

type descendantCreateResponse struct {
	Resource      ResourceOut `json:"resource"`
	Template      string      `json:"template"`
	OwnerPolicy   string      `json:"owner_policy"`
	AdminPolicies []string    `json:"admin_policies"`
	Owners        []string    `json:"owners"`
}

type ownerMutationRequest struct {
	ResourcePath string `json:"resource_path"`
	Username     string `json:"username"`
}

type delegatedGrantRequest struct {
	ResourcePath string `json:"resource_path"`
	Username     string `json:"username"`
	RoleID       string `json:"role_id"`
}

func (server *Server) handleOwnershipCreateDescendant(w http.ResponseWriter, r *http.Request, body []byte) {
	var request descendantCreateRequest
	if err := json.Unmarshal(body, &request); err != nil {
		_ = newErrorResponse(fmt.Sprintf("could not parse descendant create request: %s", err.Error()), 400, nil).write(w, r)
		return
	}

	username, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}

	response, errResponse := server.createOwnedDescendant(username, request)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(response, http.StatusCreated).write(w, r)
}

func (server *Server) handleOwnershipAddOwner(w http.ResponseWriter, r *http.Request, body []byte) {
	var request ownerMutationRequest
	if err := json.Unmarshal(body, &request); err != nil {
		_ = newErrorResponse(fmt.Sprintf("could not parse owner request: %s", err.Error()), 400, nil).write(w, r)
		return
	}
	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	if errResponse := server.requireOwnershipControl(caller, request.ResourcePath); errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	if errResponse := transactify(server.db, func(tx *sqlx.Tx) *ErrorResponse {
		template, resourceID, errResponse := templateForResource(tx, request.ResourcePath)
		if errResponse != nil {
			return errResponse
		}
		return ensureOwnerBinding(tx, template, resourceID, request.ResourcePath, request.Username, caller)
	}); errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(map[string]string{"added_owner": request.Username}, http.StatusOK).write(w, r)
}

func (server *Server) handleOwnershipRemoveOwner(w http.ResponseWriter, r *http.Request, body []byte) {
	var request ownerMutationRequest
	if err := json.Unmarshal(body, &request); err != nil {
		_ = newErrorResponse(fmt.Sprintf("could not parse owner request: %s", err.Error()), 400, nil).write(w, r)
		return
	}
	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	if errResponse := server.requireOwnershipControl(caller, request.ResourcePath); errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	if errResponse := transactify(server.db, func(tx *sqlx.Tx) *ErrorResponse {
		return removeOwnerBinding(tx, request.ResourcePath, request.Username)
	}); errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(map[string]string{"removed_owner": request.Username}, http.StatusOK).write(w, r)
}

func (server *Server) handleOwnershipGrantUser(w http.ResponseWriter, r *http.Request, body []byte) {
	var request delegatedGrantRequest
	if err := json.Unmarshal(body, &request); err != nil {
		_ = newErrorResponse(fmt.Sprintf("could not parse delegated grant request: %s", err.Error()), 400, nil).write(w, r)
		return
	}
	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	if errResponse := server.requireOwnershipControl(caller, request.ResourcePath); errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	if errResponse := transactify(server.db, func(tx *sqlx.Tx) *ErrorResponse {
		template, resourceID, errResponse := templateForResource(tx, request.ResourcePath)
		if errResponse != nil {
			return errResponse
		}
		if !template.roleIsDelegable(request.RoleID) {
			msg := fmt.Sprintf("role %s is not delegable for template %s", request.RoleID, template.Name)
			return newErrorResponse(msg, 400, nil)
		}
		return ensureDelegatedUserBinding(tx, template, resourceID, request.ResourcePath, request.Username, request.RoleID, caller)
	}); errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(map[string]string{"granted": request.Username, "role_id": request.RoleID}, http.StatusOK).write(w, r)
}

func (server *Server) handleOwnershipRevokeUser(w http.ResponseWriter, r *http.Request, body []byte) {
	var request delegatedGrantRequest
	if err := json.Unmarshal(body, &request); err != nil {
		_ = newErrorResponse(fmt.Sprintf("could not parse delegated revoke request: %s", err.Error()), 400, nil).write(w, r)
		return
	}
	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	if errResponse := server.requireOwnershipControl(caller, request.ResourcePath); errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	if errResponse := transactify(server.db, func(tx *sqlx.Tx) *ErrorResponse {
		return removeDelegatedUserBinding(tx, request.ResourcePath, request.Username, request.RoleID)
	}); errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(map[string]string{"revoked": request.Username, "role_id": request.RoleID}, http.StatusOK).write(w, r)
}

func (server *Server) createOwnedDescendant(username string, request descendantCreateRequest) (*descendantCreateResponse, *ErrorResponse) {
	request.ParentPath = cleanResourcePath(request.ParentPath)
	request.Name = strings.TrimSpace(request.Name)
	if request.ParentPath == "" || request.Name == "" || strings.Contains(request.Name, "/") {
		return nil, newErrorResponse("parent_path and a single path-segment name are required", 400, nil)
	}
	if errResponse := server.authorizeCreateDescendant(username, request.ParentPath); errResponse != nil {
		return nil, errResponse
	}

	var response *descendantCreateResponse
	errResponse := transactify(server.db, func(tx *sqlx.Tx) *ErrorResponse {
		template, errResponse := templateForParent(tx, request.ParentPath, request.Template)
		if errResponse != nil {
			return errResponse
		}

		childPath := cleanResourcePath(request.ParentPath + "/" + request.Name)
		if existing, err := resourceWithPathTx(tx, childPath); err != nil {
			return newErrorResponse(fmt.Sprintf("resource lookup failed: %s", err.Error()), 500, &err)
		} else if existing != nil {
			return newErrorResponse(fmt.Sprintf("resource already exists: %s", childPath), 409, nil)
		}

		if errResponse := ensureOwnershipBaseRoles(tx, template.OwnerRole); errResponse != nil {
			return errResponse
		}
		resource := &ResourceIn{Path: childPath, Description: request.Description}
		if template.ChildContainerName.Valid {
			resource.Subresources = []ResourceIn{{Name: template.ChildContainerName.String}}
		}
		if errResponse := resource.createRecursively(tx); errResponse != nil {
			return errResponse
		}

		resourceFromQuery, err := resourceWithPathTx(tx, childPath)
		if err != nil {
			return newErrorResponse(fmt.Sprintf("resource lookup failed after create: %s", err.Error()), 500, &err)
		}
		if resourceFromQuery == nil {
			return newErrorResponse("resource was not found after create", 500, nil)
		}

		if errResponse := ensureOwnerBinding(tx, template, resourceFromQuery.ID, childPath, username, username); errResponse != nil {
			return errResponse
		}
		adminPolicies := []string{}
		for _, groupName := range template.DefaultAdminGroups {
			policyName, errResponse := ensureProtectedAdminBinding(tx, template, resourceFromQuery.ID, childPath, groupName, username)
			if errResponse != nil {
				return errResponse
			}
			adminPolicies = append(adminPolicies, policyName)
		}
		if template.ChildContainerName.Valid {
			containerPath := childPath + "/" + template.ChildContainerName.String
			container, err := resourceWithPathTx(tx, containerPath)
			if err != nil {
				return newErrorResponse(fmt.Sprintf("container lookup failed after create: %s", err.Error()), 500, &err)
			}
			if container == nil {
				return newErrorResponse(fmt.Sprintf("container resource was not found after create: %s", containerPath), 500, nil)
			}
			policiesToAttach := append([]string{generatedPolicyName("owner", childPath, template.OwnerRole)}, adminPolicies...)
			for _, policyName := range policiesToAttach {
				if errResponse := attachPolicyToResource(tx, policyName, container.ID); errResponse != nil {
					return errResponse
				}
			}
		}
		response = &descendantCreateResponse{
			Resource:      resourceFromQuery.standardize(),
			Template:      template.Name,
			OwnerPolicy:   generatedPolicyName("owner", childPath, template.OwnerRole),
			AdminPolicies: adminPolicies,
			Owners:        []string{username},
		}
		return nil
	})
	if errResponse != nil {
		return nil, errResponse
	}
	return response, nil
}

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

func templateForParent(tx *sqlx.Tx, parentPath string, templateName string) (*ownershipTemplate, *ErrorResponse) {
	templates, err := listOwnershipTemplates(tx)
	if err != nil {
		return nil, newErrorResponse(fmt.Sprintf("ownership template query failed: %s", err.Error()), 500, &err)
	}
	for _, template := range templates {
		if templateName != "" && template.Name != templateName {
			continue
		}
		matched, err := regexp.MatchString(template.ParentPathPattern, parentPath)
		if err != nil {
			return nil, newErrorResponse(fmt.Sprintf("invalid ownership template pattern %s: %s", template.Name, err.Error()), 500, &err)
		}
		if matched {
			return &template, nil
		}
	}
	return nil, newErrorResponse(fmt.Sprintf("no ownership template allows children under %s", parentPath), 400, nil)
}

func templateForResource(tx *sqlx.Tx, resourcePath string) (*ownershipTemplate, int64, *ErrorResponse) {
	resource, err := resourceWithPathTx(tx, resourcePath)
	if err != nil {
		return nil, 0, newErrorResponse(fmt.Sprintf("resource lookup failed: %s", err.Error()), 500, &err)
	}
	if resource == nil {
		return nil, 0, newErrorResponse(fmt.Sprintf("resource does not exist: %s", resourcePath), 404, nil)
	}
	stmt := `
		SELECT ownership_template.*
		FROM generated_policy_metadata
		JOIN ownership_template ON ownership_template.name = generated_policy_metadata.template_name
		WHERE generated_policy_metadata.resource_id = $1
		LIMIT 1
	`
	var template ownershipTemplate
	if err := tx.Get(&template, stmt, resource.ID); err != nil {
		return nil, 0, newErrorResponse(fmt.Sprintf("ownership template not found for %s", resourcePath), 404, &err)
	}
	return &template, resource.ID, nil
}

func listOwnershipTemplates(tx *sqlx.Tx) ([]ownershipTemplate, error) {
	var templates []ownershipTemplate
	stmt := `
		SELECT
			name,
			parent_path_pattern,
			child_kind,
			child_container_name,
			owner_role,
			admin_role,
			default_admin_groups,
			delegable_roles
		FROM ownership_template
		ORDER BY name
	`
	err := tx.Select(&templates, stmt)
	return templates, err
}

func resourceWithPathTx(tx *sqlx.Tx, path string) (*ResourceFromQuery, error) {
	path = FormatPathForDb(path)
	resources := []ResourceFromQuery{}
	stmt := `
		SELECT
			parent.id,
			parent.name,
			parent.path,
			parent.tag,
			parent.description,
			array(
				SELECT child.path
				FROM resource AS child
				WHERE child.path ~ (
					CAST ((ltree2text(parent.path) || '.*{1}') AS lquery)
				)
			) AS subresources
		FROM resource AS parent
		WHERE parent.path = text2ltree(CAST ($1 AS TEXT))
		GROUP BY parent.id
		LIMIT 1
	`
	err := tx.Select(&resources, stmt, path)
	if len(resources) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	resource := resources[0]
	return &resource, nil
}

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
		return newErrorResponse(fmt.Sprintf("failed to remove generated user binding: %s", err.Error()), 500, &err)
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
	if _, err := tx.Exec(stmt, args...); err != nil {
		return newErrorResponse(fmt.Sprintf("failed to remove ownership binding metadata: %s", err.Error()), 500, &err)
	}
	return nil
}

func generatedPolicyName(kind string, resourcePath string, roleID string) string {
	resourcePart := strings.Trim(FormatPathForDb(resourcePath), ".")
	return fmt.Sprintf("generated.%s.%s.%s", kind, resourcePart, roleID)
}

func cleanResourcePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = regSlashes.ReplaceAllLiteralString("/"+strings.Trim(path, "/"), "/")
	return path
}

func (template *ownershipTemplate) roleIsDelegable(roleID string) bool {
	for _, delegableRole := range template.DelegableRoles {
		if delegableRole == roleID {
			return true
		}
	}
	return false
}

func generatedPolicyIsProtected(tx *sqlx.Tx, policyName string) (bool, *ErrorResponse) {
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
		return false, newErrorResponse(fmt.Sprintf("generated policy metadata lookup failed: %s", err.Error()), 500, &err)
	}
	return protected, nil
}

func resourceHasProtectedOwnership(tx *sqlx.Tx, resourcePath string) (bool, *ErrorResponse) {
	var count int
	stmt := `
		SELECT COUNT(*)
		FROM generated_policy_metadata
		JOIN policy_resource ON generated_policy_metadata.policy_id = policy_resource.policy_id
		JOIN resource ON policy_resource.resource_id = resource.id
		WHERE resource.path = text2ltree($1)
		AND generated_policy_metadata.protected = TRUE
	`
	if err := tx.Get(&count, stmt, FormatPathForDb(resourcePath)); err != nil {
		return false, newErrorResponse(fmt.Sprintf("resource ownership metadata lookup failed: %s", err.Error()), 500, &err)
	}
	return count > 0, nil
}
