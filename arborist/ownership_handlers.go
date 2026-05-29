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
		_ = newErrorResponse("resource_path is required", http.StatusBadRequest, nil).write(w, r)
		return
	}
	includeChildren := strings.EqualFold(r.URL.Query().Get("include_children"), "true")

	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	if errResponse := server.requireOwnershipControl(caller, resourcePath); errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}

	response, errResponse := server.readOwnershipResource(resourcePath, includeChildren)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(response, http.StatusOK).write(w, r)
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
