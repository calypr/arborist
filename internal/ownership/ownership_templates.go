package ownership

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/calypr/arborist/internal/authz/store/resource"
	"github.com/jmoiron/sqlx"
)

func templateForParent(tx *sqlx.Tx, parentPath string, templateName string) (*OwnershipTemplate, *coreauthz.ErrorResponse) {
	templates, err := listOwnershipTemplates(tx)
	if err != nil {
		return nil, coreauthz.NewErrorResponse(fmt.Sprintf("ownership template query failed: %s", err.Error()), 500, &err)
	}
	for _, template := range templates {
		if templateName != "" && template.Name != templateName {
			continue
		}
		matched, err := regexp.MatchString(template.ParentPathPattern, parentPath)
		if err != nil {
			return nil, coreauthz.NewErrorResponse(fmt.Sprintf("invalid ownership template pattern %s: %s", template.Name, err.Error()), 500, &err)
		}
		if matched {
			return &template, nil
		}
	}
	return nil, coreauthz.NewErrorResponse(fmt.Sprintf("no ownership template allows children under %s", parentPath), 400, nil)
}

func resolveOwnershipTarget(tx *sqlx.Tx, resourcePath string) (*OwnershipTarget, *coreauthz.ErrorResponse) {
	resource, err := resourceWithPathTx(tx, resourcePath)
	if err != nil {
		return nil, coreauthz.NewErrorResponse(fmt.Sprintf("resource lookup failed: %s", err.Error()), 500, &err)
	}
	if resource == nil {
		return nil, coreauthz.NewErrorResponse(fmt.Sprintf("resource does not exist: %s", resourcePath), 404, nil)
	}
	stmt := `
		SELECT ownership_template.*
		FROM generated_policy_metadata
		JOIN ownership_template ON ownership_template.name = generated_policy_metadata.template_name
		WHERE generated_policy_metadata.resource_id = $1
		LIMIT 1
	`
	var template OwnershipTemplate
	if err := tx.Get(&template, stmt, resource.ID); err == nil {
		return NewManagedOwnershipTarget(&template, resource.ID, resourcePath), nil
	} else if err != sql.ErrNoRows {
		return nil, coreauthz.NewErrorResponse(fmt.Sprintf("ownership template lookup failed for %s: %s", resourcePath, err.Error()), 500, &err)
	}

	stmt = `
		SELECT ownership_template.*
		FROM policy_resource
		JOIN generated_policy_metadata ON generated_policy_metadata.policy_id = policy_resource.policy_id
		JOIN ownership_template ON ownership_template.name = generated_policy_metadata.template_name
		WHERE policy_resource.resource_id = $1
		LIMIT 1
	`
	if err := tx.Get(&template, stmt, resource.ID); err != nil {
		if err != sql.ErrNoRows {
			return nil, coreauthz.NewErrorResponse(fmt.Sprintf("ownership template lookup failed for %s: %s", resourcePath, err.Error()), 500, &err)
		}
		containerTemplate, anchorPath, errResponse := templateForChildContainer(tx, resourcePath)
		if errResponse != nil {
			return nil, errResponse
		}
		if containerTemplate != nil {
			return NewChildContainerOwnershipTarget(containerTemplate, resource.ID, resourcePath, anchorPath), nil
		}
		parentPath, ok := parentResourcePath(resourcePath)
		if ok {
			parentTemplate, parentErrResponse := templateForParent(tx, parentPath, "")
			if parentErrResponse == nil {
				return NewManagedOwnershipTarget(parentTemplate, resource.ID, resourcePath), nil
			}
		}
		return nil, coreauthz.NewErrorResponse(fmt.Sprintf("ownership template not found for %s", resourcePath), 404, &err)
	}
	return NewManagedOwnershipTarget(&template, resource.ID, resourcePath), nil
}

func templateForResource(tx *sqlx.Tx, resourcePath string) (*OwnershipTemplate, int64, *coreauthz.ErrorResponse) {
	target, errResponse := resolveOwnershipTarget(tx, resourcePath)
	if errResponse != nil {
		return nil, 0, errResponse
	}
	return target.Template, target.ResourceID, nil
}

func templateForChildContainer(tx *sqlx.Tx, resourcePath string) (*OwnershipTemplate, string, *coreauthz.ErrorResponse) {
	resourcePath = coreauthz.CleanResourcePath(resourcePath)
	pathParts := strings.Split(strings.Trim(resourcePath, "/"), "/")
	if len(pathParts) < 2 {
		return nil, "", nil
	}
	containerName := pathParts[len(pathParts)-1]
	parentPath := "/" + strings.Join(pathParts[:len(pathParts)-1], "/")
	parentPathParts := strings.Split(strings.Trim(parentPath, "/"), "/")
	if len(parentPathParts) < 1 {
		return nil, "", nil
	}
	parentCreatePath := "/" + strings.Join(parentPathParts[:len(parentPathParts)-1], "/")

	templates, err := listOwnershipTemplates(tx)
	if err != nil {
		return nil, "", coreauthz.NewErrorResponse(fmt.Sprintf("ownership template query failed: %s", err.Error()), 500, &err)
	}
	template, err := matchChildContainerTemplate(templates, containerName, parentCreatePath)
	if err != nil {
		return nil, "", coreauthz.NewErrorResponse(err.Error(), 500, &err)
	}
	if template != nil {
		return template, parentPath, nil
	}
	return nil, "", nil
}

func matchChildContainerTemplate(templates []OwnershipTemplate, containerName string, parentCreatePath string) (*OwnershipTemplate, error) {
	for _, template := range templates {
		if !template.ChildContainerName.Valid || template.ChildContainerName.String != containerName {
			continue
		}
		matched, err := regexp.MatchString(template.ParentPathPattern, parentCreatePath)
		if err != nil {
			return nil, fmt.Errorf("invalid ownership template pattern %s: %s", template.Name, err.Error())
		}
		if matched {
			return &template, nil
		}
	}
	return nil, nil
}

func listOwnershipTemplates(tx *sqlx.Tx) ([]OwnershipTemplate, error) {
	var templates []OwnershipTemplate
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

func resourceWithPathTx(tx *sqlx.Tx, path string) (*resource.ResourceFromQuery, error) {
	path = coreauthz.FormatPathForDb(path)
	resources := []resource.ResourceFromQuery{}
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

func (template *OwnershipTemplate) roleIsGrantable(roleID string) bool {
	for _, grantableRole := range template.GrantableRoles {
		if grantableRole == roleID {
			return true
		}
	}
	return false
}
