package arborist

import (
	"database/sql"
	"strings"

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

func cleanResourcePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = regSlashes.ReplaceAllLiteralString("/"+strings.Trim(path, "/"), "/")
	return path
}
