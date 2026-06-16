package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/calypr/arborist/internal/ownership"
)

func (server *Server) handleOwnershipResourceRead(w http.ResponseWriter, r *http.Request) {
	resourcePath := coreauthz.CleanResourcePath(r.URL.Query().Get("resource_path"))
	if resourcePath == "" {
		server.writeError(w, r, coreauthz.NewErrorResponse("resource_path is required", http.StatusBadRequest, nil))
		return
	}
	includeChildren := strings.EqualFold(r.URL.Query().Get("include_children"), "true")
	includeAdmins := !strings.EqualFold(r.URL.Query().Get("include_admins"), "false")

	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	response, errResponse := ownership.NewService(server.db, server.stmts).ReadResource(caller, resourcePath, ownership.ResourceReadOptions{
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
	resourcePath := coreauthz.CleanResourcePath(r.URL.Query().Get("resource_path"))
	if resourcePath == "" {
		server.writeError(w, r, coreauthz.NewErrorResponse("resource_path is required", http.StatusBadRequest, nil))
		return
	}

	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := ownership.NewService(server.db, server.stmts).DeleteResource(caller, resourcePath); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}

	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleOwnershipCreateDescendant(w http.ResponseWriter, r *http.Request, body []byte) {
	var request ownership.DescendantCreateRequest
	if err := json.Unmarshal(body, &request); err != nil {
		server.writeError(w, r, coreauthz.NewErrorResponse(fmt.Sprintf("could not parse descendant create request: %s", err.Error()), 400, nil))
		return
	}

	username, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}

	response, errResponse := ownership.NewService(server.db, server.stmts).CreateOwnedDescendant(username, request)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(response, http.StatusCreated).write(w, r)
}

func (server *Server) handleOwnershipAddOwner(w http.ResponseWriter, r *http.Request, body []byte) {
	var request ownership.OwnerMutationRequest
	if err := json.Unmarshal(body, &request); err != nil {
		server.writeError(w, r, coreauthz.NewErrorResponse(fmt.Sprintf("could not parse owner request: %s", err.Error()), 400, nil))
		return
	}
	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := ownership.NewService(server.db, server.stmts).AddOwner(caller, request); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(map[string]string{"added_owner": request.Username}, http.StatusOK).write(w, r)
}

func (server *Server) handleOwnershipRemoveOwner(w http.ResponseWriter, r *http.Request, body []byte) {
	var request ownership.OwnerMutationRequest
	if err := json.Unmarshal(body, &request); err != nil {
		server.writeError(w, r, coreauthz.NewErrorResponse(fmt.Sprintf("could not parse owner request: %s", err.Error()), 400, nil))
		return
	}
	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := ownership.NewService(server.db, server.stmts).RemoveOwner(caller, request); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(map[string]string{"removed_owner": request.Username}, http.StatusOK).write(w, r)
}
