package ownership

import (
	"fmt"
	"net/http"
	"strings"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/calypr/arborist/internal/authz/engine"
	"github.com/calypr/arborist/internal/authz/epoch"
	"github.com/calypr/arborist/internal/authz/store/resource"
	"github.com/jmoiron/sqlx"
)

type Service struct {
	DB    *sqlx.DB
	Stmts *coreauthz.CachedStmts
}

func NewService(db *sqlx.DB, stmts *coreauthz.CachedStmts) *Service {
	return &Service{DB: db, Stmts: stmts}
}

func (s *Service) authorizeCreateDescendant(username string, parentPath string) *coreauthz.ErrorResponse {
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
	err := s.DB.Get(
		&authorized,
		stmt,
		strings.ToLower(username),
		coreauthz.FormatPathForDb(parentPath),
		"arborist",
		coreauthz.CreateDescendantMethod,
		coreauthz.AnonymousGroup,
		coreauthz.LoggedInGroup,
	)
	if err != nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("create-descendant authorization failed: %s", err.Error()), 500, &err)
	}
	if !authorized {
		return coreauthz.NewErrorResponse(fmt.Sprintf("user is not allowed to create descendants under %s", parentPath), http.StatusForbidden, nil)
	}
	return nil
}

func (s *Service) RequireOwnershipControl(username string, resourcePath string) *coreauthz.ErrorResponse {
	resourcePath = coreauthz.CleanResourcePath(resourcePath)
	if errResponse := s.requireDirectOwner(username, resourcePath); errResponse == nil {
		return nil
	} else if errResponse.HTTPError.Code >= http.StatusInternalServerError {
		return errResponse
	}
	return s.requireAuthzMethod(username, resourcePath, "arborist", "manage-owners", "ownership authorization")
}

func (s *Service) RequireOwnershipDeleteControl(username string, resourcePath string) *coreauthz.ErrorResponse {
	resourcePath = coreauthz.CleanResourcePath(resourcePath)
	if errResponse := s.requireDirectOwner(username, resourcePath); errResponse == nil {
		return nil
	} else if errResponse.HTTPError.Code >= http.StatusInternalServerError {
		return errResponse
	}

	allowed := []struct {
		service string
		method  string
	}{
		{service: "arborist", method: "manage-owners"},
		{service: "*", method: "delete"},
	}
	for _, permission := range allowed {
		errResponse := s.requireAuthzMethod(username, resourcePath, permission.service, permission.method, "ownership delete authorization")
		if errResponse == nil {
			return nil
		}
		if errResponse.HTTPError.Code >= http.StatusInternalServerError {
			return errResponse
		}
	}
	return coreauthz.NewErrorResponse(fmt.Sprintf("user is not allowed to delete ownership resource %s", resourcePath), http.StatusForbidden, nil)
}

func (s *Service) requireDirectOwner(username string, resourcePath string) *coreauthz.ErrorResponse {
	resourcePath = coreauthz.CleanResourcePath(resourcePath)
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
	if err := s.DB.Get(&count, stmt, coreauthz.SubjectTypeUser, strings.ToLower(username), coreauthz.FormatPathForDb(resourcePath)); err != nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("owner lookup failed: %s", err.Error()), 500, &err)
	}
	if count > 0 {
		return nil
	}
	return coreauthz.NewErrorResponse(fmt.Sprintf("user is not an owner for %s", resourcePath), http.StatusForbidden, nil)
}

func (s *Service) requireAuthzMethod(username string, resourcePath string, service string, method string, context string) *coreauthz.ErrorResponse {
	request := (&engine.AuthRequest{
		Username: username,
		Resource: resourcePath,
		Service:  service,
		Method:   method,
	}).WithStmts(s.Stmts)
	auth, err := engine.AuthorizeUser(request)
	if err != nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("%s failed: %s", context, err.Error()), 500, &err)
	}
	if !auth.Auth {
		return coreauthz.NewErrorResponse(fmt.Sprintf("user is not allowed to %s:%s on %s", service, method, resourcePath), http.StatusForbidden, nil)
	}
	return nil
}

func (s *Service) CreateOwnedDescendant(username string, request DescendantCreateRequest) (*DescendantCreateResponse, *coreauthz.ErrorResponse) {
	request.ParentPath = coreauthz.CleanResourcePath(request.ParentPath)
	request.Name = strings.TrimSpace(request.Name)
	if request.ParentPath == "" || request.Name == "" || strings.Contains(request.Name, "/") {
		return nil, coreauthz.NewErrorResponse("parent_path and a single path-segment name are required", 400, nil)
	}
	if errResponse := s.authorizeCreateDescendant(username, request.ParentPath); errResponse != nil {
		return nil, errResponse
	}

	var response *DescendantCreateResponse
	errResponse := epoch.Transactify(s.DB, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		template, errResponse := TemplateForParent(tx, request.ParentPath, request.Template)
		if errResponse != nil {
			return errResponse
		}

		childPath := coreauthz.CleanResourcePath(request.ParentPath + "/" + request.Name)
		if existing, err := ResourceWithPathTx(tx, childPath); err != nil {
			return coreauthz.NewErrorResponse(fmt.Sprintf("resource lookup failed: %s", err.Error()), 500, &err)
		} else if existing != nil {
			return coreauthz.NewErrorResponse(fmt.Sprintf("resource already exists: %s", childPath), 409, nil)
		}

		if errResponse := ensureOwnershipBaseRolesForTemplate(tx, template.OwnerRole); errResponse != nil {
			return errResponse
		}
		childResource := &resource.ResourceIn{Path: childPath, Description: request.Description}
		if template.ChildContainerName.Valid {
			childResource.Subresources = []resource.ResourceIn{{Name: template.ChildContainerName.String}}
		}
		if errResponse := childResource.CreateRecursively(tx); errResponse != nil {
			return errResponse
		}

		resourceFromQuery, err := ResourceWithPathTx(tx, childPath)
		if err != nil {
			return coreauthz.NewErrorResponse(fmt.Sprintf("resource lookup failed after create: %s", err.Error()), 500, &err)
		}
		if resourceFromQuery == nil {
			return coreauthz.NewErrorResponse("resource was not found after create", 500, nil)
		}

		if errResponse := ensureOwnerBindingForTemplate(tx, template, resourceFromQuery.ID, childPath, username, username); errResponse != nil {
			return errResponse
		}
		adminPolicies := []string{}
		for _, groupName := range template.DefaultAdminGroups {
			policyName, errResponse := ensureProtectedAdminBindingForTemplate(tx, template, resourceFromQuery.ID, childPath, groupName, username)
			if errResponse != nil {
				return errResponse
			}
			adminPolicies = append(adminPolicies, policyName)
		}
		if template.ChildContainerName.Valid {
			containerPath := childPath + "/" + template.ChildContainerName.String
			container, err := ResourceWithPathTx(tx, containerPath)
			if err != nil {
				return coreauthz.NewErrorResponse(fmt.Sprintf("container lookup failed after create: %s", err.Error()), 500, &err)
			}
			if container == nil {
				return coreauthz.NewErrorResponse(fmt.Sprintf("container resource was not found after create: %s", containerPath), 500, nil)
			}
			policiesToAttach := append([]string{generatedPolicyNameForRole("owner", childPath, template.OwnerRole)}, adminPolicies...)
			for _, policyName := range policiesToAttach {
				if errResponse := attachPolicyToResourceByName(tx, policyName, container.ID); errResponse != nil {
					return errResponse
				}
			}
		}
		if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
			return errResponse
		}
		if errResponse := epoch.BumpResourceAuthzEpochTx(tx, request.ParentPath); errResponse != nil {
			return errResponse
		}
		if errResponse := epoch.BumpResourceAuthzEpochTx(tx, childPath); errResponse != nil {
			return errResponse
		}
		if errResponse := epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeUser, username); errResponse != nil {
			return errResponse
		}
		for _, groupName := range template.DefaultAdminGroups {
			if errResponse := epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeGroup, groupName); errResponse != nil {
				return errResponse
			}
		}
		response = &DescendantCreateResponse{
			Resource:      resourceFromQuery.Standardize(),
			Template:      template.Name,
			OwnerPolicy:   generatedPolicyNameForRole("owner", childPath, template.OwnerRole),
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

func (s *Service) DeleteResource(caller string, resourcePath string) *coreauthz.ErrorResponse {
	resourcePath = coreauthz.CleanResourcePath(resourcePath)
	if resourcePath == "" || resourcePath == "/" {
		return coreauthz.NewErrorResponse("resource_path is required", 400, nil)
	}
	if errResponse := s.RequireOwnershipDeleteControl(caller, resourcePath); errResponse != nil {
		return errResponse
	}
	return epoch.Transactify(s.DB, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		if errResponse := deleteOwnershipResource(tx, resourcePath); errResponse != nil {
			return errResponse
		}
		if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
			return errResponse
		}
		return epoch.BumpResourceAuthzEpochTx(tx, resourcePath)
	})
}

func (s *Service) AddOwner(caller string, request OwnerMutationRequest) *coreauthz.ErrorResponse {
	request.ResourcePath = coreauthz.CleanResourcePath(request.ResourcePath)
	if errResponse := s.RequireOwnershipControl(caller, request.ResourcePath); errResponse != nil {
		return errResponse
	}
	return epoch.Transactify(s.DB, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		target, errResponse := ResolveOwnershipTarget(tx, request.ResourcePath)
		if errResponse != nil {
			return errResponse
		}
		if errResponse := EnsureOwnerBindingForTarget(tx, target, request.Username, caller); errResponse != nil {
			return errResponse
		}
		if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
			return errResponse
		}
		if errResponse := epoch.BumpResourceAuthzEpochTx(tx, request.ResourcePath); errResponse != nil {
			return errResponse
		}
		return epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeUser, request.Username)
	})
}

func (s *Service) RemoveOwner(caller string, request OwnerMutationRequest) *coreauthz.ErrorResponse {
	request.ResourcePath = coreauthz.CleanResourcePath(request.ResourcePath)
	if errResponse := s.RequireOwnershipControl(caller, request.ResourcePath); errResponse != nil {
		return errResponse
	}
	return epoch.Transactify(s.DB, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		if errResponse := removeOwnerBindingForResource(tx, request.ResourcePath, request.Username); errResponse != nil {
			return errResponse
		}
		if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
			return errResponse
		}
		if errResponse := epoch.BumpResourceAuthzEpochTx(tx, request.ResourcePath); errResponse != nil {
			return errResponse
		}
		return epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeUser, request.Username)
	})
}
