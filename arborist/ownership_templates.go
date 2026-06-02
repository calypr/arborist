package arborist

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/jmoiron/sqlx"
)

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

func resolveOwnershipTarget(tx *sqlx.Tx, resourcePath string) (*ownershipTarget, *ErrorResponse) {
	resource, err := resourceWithPathTx(tx, resourcePath)
	if err != nil {
		return nil, newErrorResponse(fmt.Sprintf("resource lookup failed: %s", err.Error()), 500, &err)
	}
	if resource == nil {
		return nil, newErrorResponse(fmt.Sprintf("resource does not exist: %s", resourcePath), 404, nil)
	}
	stmt := `
		SELECT ownership_template.*
		FROM generated_policy_metadata
		JOIN ownership_template ON ownership_template.name = generated_policy_metadata.template_name
		WHERE generated_policy_metadata.resource_id = $1
		LIMIT 1
	`
	var template ownershipTemplate
	if err := tx.Get(&template, stmt, resource.ID); err == nil {
		return newManagedOwnershipTarget(&template, resource.ID, resourcePath), nil
	} else if err != sql.ErrNoRows {
		return nil, newErrorResponse(fmt.Sprintf("ownership template lookup failed for %s: %s", resourcePath, err.Error()), 500, &err)
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
			return nil, newErrorResponse(fmt.Sprintf("ownership template lookup failed for %s: %s", resourcePath, err.Error()), 500, &err)
		}
		containerTemplate, anchorPath, errResponse := templateForChildContainer(tx, resourcePath)
		if errResponse != nil {
			return nil, errResponse
		}
		if containerTemplate != nil {
			return newChildContainerOwnershipTarget(containerTemplate, resource.ID, resourcePath, anchorPath), nil
		}
		parentPath, ok := parentResourcePath(resourcePath)
		if ok {
			parentTemplate, parentErrResponse := templateForParent(tx, parentPath, "")
			if parentErrResponse == nil {
				return newManagedOwnershipTarget(parentTemplate, resource.ID, resourcePath), nil
			}
		}
		return nil, newErrorResponse(fmt.Sprintf("ownership template not found for %s", resourcePath), 404, &err)
	}
	return newManagedOwnershipTarget(&template, resource.ID, resourcePath), nil
}

func templateForResource(tx *sqlx.Tx, resourcePath string) (*ownershipTemplate, int64, *ErrorResponse) {
	target, errResponse := resolveOwnershipTarget(tx, resourcePath)
	if errResponse != nil {
		return nil, 0, errResponse
	}
	return target.Template, target.ResourceID, nil
}

func templateForChildContainer(tx *sqlx.Tx, resourcePath string) (*ownershipTemplate, string, *ErrorResponse) {
	resourcePath = cleanResourcePath(resourcePath)
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
		return nil, "", newErrorResponse(fmt.Sprintf("ownership template query failed: %s", err.Error()), 500, &err)
	}
	template, err := matchChildContainerTemplate(templates, containerName, parentCreatePath)
	if err != nil {
		return nil, "", newErrorResponse(err.Error(), 500, &err)
	}
	if template != nil {
		return template, parentPath, nil
	}
	return nil, "", nil
}

func matchChildContainerTemplate(templates []ownershipTemplate, containerName string, parentCreatePath string) (*ownershipTemplate, error) {
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

func (template *ownershipTemplate) roleIsDelegable(roleID string) bool {
	for _, delegableRole := range template.DelegableRoles {
		if delegableRole == roleID {
			return true
		}
	}
	return false
}
