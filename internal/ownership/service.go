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

type descendantCreateState struct {
	template       *OwnershipTemplate
	childPath      string
	resource       *resource.ResourceFromQuery
	adminPolicies  []string
	ownerPolicy    string
	responseOwners []string
}

func NewService(db *sqlx.DB, stmts *coreauthz.CachedStmts) *Service {
	return &Service{DB: db, Stmts: stmts}
}

func (s *Service) authorizeCreateDescendant(username string, parentPath string) *coreauthz.ErrorResponse {
	request := (&engine.AuthRequest{
		Username: username,
		Resource: parentPath,
		Service:  "arborist",
		Method:   coreauthz.CreateDescendantMethod,
	}).WithStmts(s.Stmts)
	auth, err := engine.AuthorizeUserExact(request)
	if err != nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("create-descendant authorization failed: %s", err.Error()), 500, &err)
	}
	if !auth.Auth {
		return coreauthz.NewErrorResponse(fmt.Sprintf("user is not allowed to create descendants under %s", parentPath), http.StatusForbidden, nil)
	}
	return nil
}

func (s *Service) validateDescendantCreateRequest(request DescendantCreateRequest) (DescendantCreateRequest, string, *coreauthz.ErrorResponse) {
	request.ParentPath = coreauthz.CleanResourcePath(request.ParentPath)
	request.Name = strings.TrimSpace(request.Name)
	if request.ParentPath == "" || request.Name == "" || strings.Contains(request.Name, "/") {
		return request, "", coreauthz.NewErrorResponse("parent_path and a single path-segment name are required", 400, nil)
	}
	childPath := coreauthz.CleanResourcePath(request.ParentPath + "/" + request.Name)
	return request, childPath, nil
}

func (s *Service) prepareDescendantTemplate(tx *sqlx.Tx, parentPath string, requestedTemplate string) (*OwnershipTemplate, *coreauthz.ErrorResponse) {
	template, errResponse := TemplateForParent(tx, parentPath, requestedTemplate)
	if errResponse != nil {
		return nil, errResponse
	}
	if errResponse := ensureOwnershipBaseRolesForTemplate(tx, template.OwnerRole); errResponse != nil {
		return nil, errResponse
	}
	return template, nil
}

func (s *Service) createDescendantResource(tx *sqlx.Tx, childPath string, description *string, template *OwnershipTemplate) (*resource.ResourceFromQuery, *coreauthz.ErrorResponse) {
	if existing, err := ResourceWithPathTx(tx, childPath); err != nil {
		return nil, coreauthz.NewErrorResponse(fmt.Sprintf("resource lookup failed: %s", err.Error()), 500, &err)
	} else if existing != nil {
		return nil, coreauthz.NewErrorResponse(fmt.Sprintf("resource already exists: %s", childPath), 409, nil)
	}

	childResource := &resource.ResourceIn{Path: childPath, Description: description}
	if template.ChildContainerName.Valid {
		childResource.Subresources = []resource.ResourceIn{{Name: template.ChildContainerName.String}}
	}
	if errResponse := childResource.CreateRecursively(tx); errResponse != nil {
		return nil, errResponse
	}

	resourceFromQuery, err := ResourceWithPathTx(tx, childPath)
	if err != nil {
		return nil, coreauthz.NewErrorResponse(fmt.Sprintf("resource lookup failed after create: %s", err.Error()), 500, &err)
	}
	if resourceFromQuery == nil {
		return nil, coreauthz.NewErrorResponse("resource was not found after create", 500, nil)
	}
	return resourceFromQuery, nil
}

func (s *Service) materializeDescendantBindings(tx *sqlx.Tx, template *OwnershipTemplate, resourceID int64, childPath string, username string) (string, []string, []string, *coreauthz.ErrorResponse) {
	if errResponse := ensureOwnerBindingForTemplate(tx, template, resourceID, childPath, username, username); errResponse != nil {
		return "", nil, nil, errResponse
	}

	adminPolicies := []string{}
	for _, groupName := range template.DefaultAdminGroups {
		policyName, errResponse := ensureProtectedAdminBindingForTemplate(tx, template, resourceID, childPath, groupName, username)
		if errResponse != nil {
			return "", nil, nil, errResponse
		}
		adminPolicies = append(adminPolicies, policyName)
	}

	ownerPolicy := generatedPolicyNameForRole("owner", childPath, template.OwnerRole)
	return ownerPolicy, adminPolicies, []string{username}, nil
}

func (s *Service) attachDescendantContainerPolicies(tx *sqlx.Tx, template *OwnershipTemplate, childPath string, ownerPolicy string, adminPolicies []string) *coreauthz.ErrorResponse {
	if !template.ChildContainerName.Valid {
		return nil
	}

	containerPath := childPath + "/" + template.ChildContainerName.String
	container, err := ResourceWithPathTx(tx, containerPath)
	if err != nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("container lookup failed after create: %s", err.Error()), 500, &err)
	}
	if container == nil {
		return coreauthz.NewErrorResponse(fmt.Sprintf("container resource was not found after create: %s", containerPath), 500, nil)
	}

	policiesToAttach := append([]string{ownerPolicy}, adminPolicies...)
	for _, policyName := range policiesToAttach {
		if errResponse := attachPolicyToResourceByName(tx, policyName, container.ID); errResponse != nil {
			return errResponse
		}
	}
	return nil
}

func (s *Service) bumpDescendantEpochs(tx *sqlx.Tx, parentPath string, childPath string, username string, adminGroups []string) *coreauthz.ErrorResponse {
	if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
		return errResponse
	}
	if errResponse := epoch.BumpResourceAuthzEpochTx(tx, parentPath); errResponse != nil {
		return errResponse
	}
	if errResponse := epoch.BumpResourceAuthzEpochTx(tx, childPath); errResponse != nil {
		return errResponse
	}
	if errResponse := epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeUser, username); errResponse != nil {
		return errResponse
	}
	for _, groupName := range adminGroups {
		if errResponse := epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeGroup, groupName); errResponse != nil {
			return errResponse
		}
	}
	return nil
}

func (s *Service) buildDescendantCreateResponse(state *descendantCreateState) *DescendantCreateResponse {
	return &DescendantCreateResponse{
		Resource:      state.resource.Standardize(),
		Template:      state.template.Name,
		OwnerPolicy:   state.ownerPolicy,
		AdminPolicies: state.adminPolicies,
		Owners:        state.responseOwners,
	}
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
	request, childPath, errResponse := s.validateDescendantCreateRequest(request)
	if errResponse != nil {
		return nil, errResponse
	}
	if errResponse := s.authorizeCreateDescendant(username, request.ParentPath); errResponse != nil {
		return nil, errResponse
	}

	state := &descendantCreateState{childPath: childPath}
	errResponse = epoch.Transactify(s.DB, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		template, errResponse := s.prepareDescendantTemplate(tx, request.ParentPath, request.Template)
		if errResponse != nil {
			return errResponse
		}
		state.template = template

		resourceFromQuery, errResponse := s.createDescendantResource(tx, state.childPath, request.Description, state.template)
		if errResponse != nil {
			return errResponse
		}
		state.resource = resourceFromQuery

		state.ownerPolicy, state.adminPolicies, state.responseOwners, errResponse = s.materializeDescendantBindings(tx, state.template, state.resource.ID, state.childPath, username)
		if errResponse != nil {
			return errResponse
		}

		if errResponse := s.attachDescendantContainerPolicies(tx, state.template, state.childPath, state.ownerPolicy, state.adminPolicies); errResponse != nil {
			return errResponse
		}
		return s.bumpDescendantEpochs(tx, request.ParentPath, state.childPath, username, state.template.DefaultAdminGroups)
	})
	if errResponse != nil {
		return nil, errResponse
	}
	return s.buildDescendantCreateResponse(state), nil
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
