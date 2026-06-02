package arborist

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/jmoiron/sqlx"
)

func (server *Server) handleOwnershipResourceRead(w http.ResponseWriter, r *http.Request) {
	resourcePath := cleanResourcePath(r.URL.Query().Get("resource_path"))
	if resourcePath == "" {
		server.writeError(w, r, newErrorResponse("resource_path is required", http.StatusBadRequest, nil))
		return
	}
	includeChildren := strings.EqualFold(r.URL.Query().Get("include_children"), "true")
	includeAdmins := !strings.EqualFold(r.URL.Query().Get("include_admins"), "false")

	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := server.requireOwnershipControl(caller, resourcePath); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}

	response, errResponse := server.readOwnershipResource(resourcePath, ownershipResourceReadOptions{
		IncludeChildren: includeChildren,
		IncludeAdmins:   includeAdmins,
	})
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(response, http.StatusOK).write(w, r)
}

func (server *Server) handleOwnershipResourceDelete(w http.ResponseWriter, r *http.Request) {
	resourcePath := cleanResourcePath(r.URL.Query().Get("resource_path"))
	if resourcePath == "" {
		server.writeError(w, r, newErrorResponse("resource_path is required", http.StatusBadRequest, nil))
		return
	}

	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := server.requireOwnershipControl(caller, resourcePath); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}

	if errResponse := transactify(server.db, func(tx *sqlx.Tx) *ErrorResponse {
		return deleteOwnershipResource(tx, resourcePath)
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}

	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleOwnershipCreateDescendant(w http.ResponseWriter, r *http.Request, body []byte) {
	var request descendantCreateRequest
	if err := json.Unmarshal(body, &request); err != nil {
		server.writeError(w, r, newErrorResponse(fmt.Sprintf("could not parse descendant create request: %s", err.Error()), 400, nil))
		return
	}

	username, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}

	response, errResponse := server.createOwnedDescendant(username, request)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(response, http.StatusCreated).write(w, r)
}

func (server *Server) handleOwnershipAddOwner(w http.ResponseWriter, r *http.Request, body []byte) {
	var request ownerMutationRequest
	if err := json.Unmarshal(body, &request); err != nil {
		server.writeError(w, r, newErrorResponse(fmt.Sprintf("could not parse owner request: %s", err.Error()), 400, nil))
		return
	}
	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := server.requireOwnershipControl(caller, request.ResourcePath); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := transactify(server.db, func(tx *sqlx.Tx) *ErrorResponse {
		target, errResponse := resolveOwnershipTarget(tx, request.ResourcePath)
		if errResponse != nil {
			return errResponse
		}
		return ensureOwnerBindingForTarget(tx, target, request.Username, caller)
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(map[string]string{"added_owner": request.Username}, http.StatusOK).write(w, r)
}

func (server *Server) handleOwnershipRemoveOwner(w http.ResponseWriter, r *http.Request, body []byte) {
	var request ownerMutationRequest
	if err := json.Unmarshal(body, &request); err != nil {
		server.writeError(w, r, newErrorResponse(fmt.Sprintf("could not parse owner request: %s", err.Error()), 400, nil))
		return
	}
	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := server.requireOwnershipControl(caller, request.ResourcePath); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := transactify(server.db, func(tx *sqlx.Tx) *ErrorResponse {
		return removeOwnerBinding(tx, request.ResourcePath, request.Username)
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(map[string]string{"removed_owner": request.Username}, http.StatusOK).write(w, r)
}

func (server *Server) handleOwnershipGrantUser(w http.ResponseWriter, r *http.Request, body []byte) {
	var request delegatedGrantRequest
	if err := json.Unmarshal(body, &request); err != nil {
		server.writeError(w, r, newErrorResponse(fmt.Sprintf("could not parse delegated grant request: %s", err.Error()), 400, nil))
		return
	}
	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := server.requireOwnershipControl(caller, request.ResourcePath); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := transactify(server.db, func(tx *sqlx.Tx) *ErrorResponse {
		target, errResponse := resolveOwnershipTarget(tx, request.ResourcePath)
		if errResponse != nil {
			return errResponse
		}
		if !target.Template.roleIsDelegable(request.RoleID) {
			msg := fmt.Sprintf("role %s is not delegable for template %s", request.RoleID, target.Template.Name)
			return newErrorResponse(msg, 400, nil)
		}
		return ensureDelegatedUserBindingForTarget(tx, target, request.Username, request.RoleID, caller)
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(map[string]string{"granted": request.Username, "role_id": request.RoleID}, http.StatusOK).write(w, r)
}

func (server *Server) handleOwnershipRevokeUser(w http.ResponseWriter, r *http.Request, body []byte) {
	var request delegatedGrantRequest
	if err := json.Unmarshal(body, &request); err != nil {
		server.writeError(w, r, newErrorResponse(fmt.Sprintf("could not parse delegated revoke request: %s", err.Error()), 400, nil))
		return
	}
	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := server.requireOwnershipControl(caller, request.ResourcePath); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := transactify(server.db, func(tx *sqlx.Tx) *ErrorResponse {
		return removeDelegatedUserBinding(tx, request.ResourcePath, request.Username, request.RoleID)
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(map[string]string{"revoked": request.Username, "role_id": request.RoleID}, http.StatusOK).write(w, r)
}
