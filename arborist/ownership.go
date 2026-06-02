package arborist

import (
	"database/sql"
	"strings"

	"github.com/lib/pq"
)

const (
	createDescendantMethod             = "create-descendant"
	orgMemberRole                      = "org-member"
	ownershipProvider                  = "arborist-ownership"
	ownerSubjectType                   = "user"
	ownershipTargetManagedResourceKind = "managed-resource"
	ownershipTargetChildContainerKind  = "child-container"
)

type ownershipTemplate struct {
	Name               string         `db:"name"`
	Description        sql.NullString `db:"description"`
	ParentPathPattern  string         `db:"parent_path_pattern"`
	ChildKind          string         `db:"child_kind"`
	ChildContainerName sql.NullString `db:"child_container_name"`
	OwnerRole          string         `db:"owner_role"`
	AdminRole          string         `db:"admin_role"`
	DefaultAdminGroups pq.StringArray `db:"default_admin_groups"`
	DelegableRoles     pq.StringArray `db:"delegable_roles"`
}

type ownershipTarget struct {
	Kind         string
	Template     *ownershipTemplate
	ResourceID   int64
	ResourcePath string
	AnchorPath   string
	PolicyPath   string
}

func newManagedOwnershipTarget(template *ownershipTemplate, resourceID int64, resourcePath string) *ownershipTarget {
	resourcePath = cleanResourcePath(resourcePath)
	return &ownershipTarget{
		Kind:         ownershipTargetManagedResourceKind,
		Template:     template,
		ResourceID:   resourceID,
		ResourcePath: resourcePath,
		AnchorPath:   resourcePath,
		PolicyPath:   resourcePath,
	}
}

func newChildContainerOwnershipTarget(template *ownershipTemplate, resourceID int64, resourcePath string, anchorPath string) *ownershipTarget {
	resourcePath = cleanResourcePath(resourcePath)
	anchorPath = cleanResourcePath(anchorPath)
	return &ownershipTarget{
		Kind:         ownershipTargetChildContainerKind,
		Template:     template,
		ResourceID:   resourceID,
		ResourcePath: resourcePath,
		AnchorPath:   anchorPath,
		PolicyPath:   resourcePath,
	}
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
