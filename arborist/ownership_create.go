package arborist

import (
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
)

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
