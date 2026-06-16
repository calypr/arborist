package ownership

import (
	"database/sql"
	"fmt"
	"strings"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/calypr/arborist/internal/authz/store/resource"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

const (
	createDescendantMethod             = coreauthz.CreateDescendantMethod
	orgMemberRole                      = "org-member"
	ownershipProvider                  = "arborist-ownership"
	ownerSubjectType                   = "user"
	ownershipTargetManagedResourceKind = "managed-resource"
	ownershipTargetChildContainerKind  = "child-container"
)

type OwnershipTemplate struct {
	Name               string         `db:"name"`
	Description        sql.NullString `db:"description"`
	ParentPathPattern  string         `db:"parent_path_pattern"`
	ChildKind          string         `db:"child_kind"`
	ChildContainerName sql.NullString `db:"child_container_name"`
	OwnerRole          string         `db:"owner_role"`
	AdminRole          string         `db:"admin_role"`
	DefaultAdminGroups pq.StringArray `db:"default_admin_groups"`
	GrantableRoles     pq.StringArray `db:"delegable_roles"`
}

type OwnershipTarget struct {
	Kind         string
	Template     *OwnershipTemplate
	ResourceID   int64
	ResourcePath string
	AnchorPath   string
	PolicyPath   string
}

func NewManagedOwnershipTarget(template *OwnershipTemplate, resourceID int64, resourcePath string) *OwnershipTarget {
	resourcePath = coreauthz.CleanResourcePath(resourcePath)
	return &OwnershipTarget{
		Kind:         ownershipTargetManagedResourceKind,
		Template:     template,
		ResourceID:   resourceID,
		ResourcePath: resourcePath,
		AnchorPath:   resourcePath,
		PolicyPath:   resourcePath,
	}
}

func NewChildContainerOwnershipTarget(template *OwnershipTemplate, resourceID int64, resourcePath string, anchorPath string) *OwnershipTarget {
	resourcePath = coreauthz.CleanResourcePath(resourcePath)
	anchorPath = coreauthz.CleanResourcePath(anchorPath)
	return &OwnershipTarget{
		Kind:         ownershipTargetChildContainerKind,
		Template:     template,
		ResourceID:   resourceID,
		ResourcePath: resourcePath,
		AnchorPath:   anchorPath,
		PolicyPath:   resourcePath,
	}
}

type DescendantCreateRequest struct {
	ParentPath  string  `json:"parent_path"`
	Name        string  `json:"name"`
	Template    string  `json:"template,omitempty"`
	Description *string `json:"description,omitempty"`
}

type DescendantCreateResponse struct {
	Resource      resource.ResourceOut `json:"resource"`
	Template      string               `json:"template"`
	OwnerPolicy   string               `json:"owner_policy"`
	AdminPolicies []string             `json:"admin_policies"`
	Owners        []string             `json:"owners"`
}

type OwnerMutationRequest struct {
	ResourcePath string `json:"resource_path"`
	Username     string `json:"username"`
}

func parentResourcePath(resourcePath string) (string, bool) {
	resourcePath = coreauthz.CleanResourcePath(resourcePath)
	lastSlash := strings.LastIndex(resourcePath, "/")
	if lastSlash <= 0 {
		return "", false
	}
	return resourcePath[:lastSlash], true
}

func TemplateForParent(tx *sqlx.Tx, parentPath string, templateName string) (*OwnershipTemplate, *coreauthz.ErrorResponse) {
	return templateForParent(tx, parentPath, templateName)
}

func ResolveOwnershipTarget(tx *sqlx.Tx, resourcePath string) (*OwnershipTarget, *coreauthz.ErrorResponse) {
	return resolveOwnershipTarget(tx, resourcePath)
}

func ResourceWithPathTx(tx *sqlx.Tx, path string) (*resource.ResourceFromQuery, error) {
	return resourceWithPathTx(tx, path)
}

func ensureOwnershipBaseRolesForTemplate(tx *sqlx.Tx, ownerRole string) *coreauthz.ErrorResponse {
	return ensureOwnershipBaseRoles(tx, ownerRole)
}

func ensureOwnerBindingForTemplate(tx *sqlx.Tx, template *OwnershipTemplate, resourceID int64, resourcePath string, username string, createdBy string) *coreauthz.ErrorResponse {
	return ensureOwnerBinding(tx, template, resourceID, resourcePath, username, createdBy)
}

func EnsureOwnerBindingForTarget(tx *sqlx.Tx, target *OwnershipTarget, username string, createdBy string) *coreauthz.ErrorResponse {
	return ensureOwnerBindingForTarget(tx, target, username, createdBy)
}

func ensureProtectedAdminBindingForTemplate(tx *sqlx.Tx, template *OwnershipTemplate, resourceID int64, resourcePath string, groupName string, createdBy string) (string, *coreauthz.ErrorResponse) {
	return ensureProtectedAdminBinding(tx, template, resourceID, resourcePath, groupName, createdBy)
}

func EnsureProtectedAdminBindingForTarget(tx *sqlx.Tx, target *OwnershipTarget, groupName string, createdBy string) (string, *coreauthz.ErrorResponse) {
	return ensureProtectedAdminBindingForTarget(tx, target, groupName, createdBy)
}

func EnsureGeneratedPolicy(tx *sqlx.Tx, target *OwnershipTarget, roleID string, kind string, protected bool, createdBy string) (string, int64, *coreauthz.ErrorResponse) {
	return ensureGeneratedPolicy(tx, target, roleID, kind, protected, createdBy)
}

func RoleIDByName(tx *sqlx.Tx, roleName string) (int64, *coreauthz.ErrorResponse) {
	return roleIDByName(tx, roleName)
}

func attachPolicyToResourceByName(tx *sqlx.Tx, policyName string, resourceID int64) *coreauthz.ErrorResponse {
	return attachPolicyToResource(tx, policyName, resourceID)
}

func EnsureUser(tx *sqlx.Tx, username string) *coreauthz.ErrorResponse {
	return ensureUser(tx, username)
}

func removeOwnerBindingForResource(tx *sqlx.Tx, resourcePath string, username string) *coreauthz.ErrorResponse {
	return removeOwnerBinding(tx, resourcePath, username)
}

func deleteOwnershipResource(tx *sqlx.Tx, resourcePath string) *coreauthz.ErrorResponse {
	resourcePath = coreauthz.CleanResourcePath(resourcePath)
	if resourcePath == "" || resourcePath == "/" {
		return coreauthz.NewErrorResponse("resource_path is required", 400, nil)
	}
	stmt := `
		DELETE FROM policy
		USING generated_policy_metadata, resource
		WHERE policy.id = generated_policy_metadata.policy_id
		AND generated_policy_metadata.resource_id = resource.id
		AND resource.path = text2ltree($1)
	`
	if _, err := tx.Exec(stmt, coreauthz.FormatPathForDb(resourcePath)); err != nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("failed to delete generated ownership policies for %s: %s", resourcePath, err.Error()), 500, &err)
	}
	stmt = "DELETE FROM resource WHERE path = $1"
	_, err := tx.Exec(stmt, coreauthz.FormatPathForDb(resourcePath))
	if err != nil {
		return nil
	}
	return nil
}

func generatedPolicyNameForRole(kind string, resourcePath string, roleID string) string {
	return generatedPolicyName(kind, resourcePath, roleID)
}

func (template *OwnershipTemplate) RoleIsGrantable(roleID string) bool {
	return template.roleIsGrantable(roleID)
}
