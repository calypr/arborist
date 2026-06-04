package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/calypr/arborist/internal/access"
	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/calypr/arborist/internal/authz/epoch"
	"github.com/calypr/arborist/internal/ownership"
	"github.com/jmoiron/sqlx"
)

func (server *Server) handleAccessGrantUser(w http.ResponseWriter, r *http.Request, body []byte) {
	var request access.AccessUserRequest
	if err := json.Unmarshal(body, &request); err != nil {
		server.writeError(w, r, coreauthz.NewErrorResponse(fmt.Sprintf("could not parse access grant request: %s", err.Error()), 400, nil))
		return
	}
	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	authzProvider := getAuthZProvider(r)
	request = access.NormalizeAccessUserRequest(request)
	if errResponse := ownership.NewService(server.db, server.stmts).RequireOwnershipControl(caller, request.ResourcePath); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	var response *access.AccessUserResponse
	if errResponse := epoch.Transactify(server.db, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		var txErr *coreauthz.ErrorResponse
		response, txErr = access.GrantUserAccess(tx, request, caller, authzProvider)
		if txErr != nil {
			return txErr
		}
		if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
			return errResponse
		}
		if errResponse := epoch.BumpResourceAuthzEpochTx(tx, request.ResourcePath); errResponse != nil {
			return errResponse
		}
		return epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeUser, request.Username)
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(response, http.StatusOK).write(w, r)
}

func (server *Server) handleAccessRevokeUser(w http.ResponseWriter, r *http.Request, body []byte) {
	var request access.AccessUserRequest
	if err := json.Unmarshal(body, &request); err != nil {
		server.writeError(w, r, coreauthz.NewErrorResponse(fmt.Sprintf("could not parse access revoke request: %s", err.Error()), 400, nil))
		return
	}
	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	authzProvider := getAuthZProvider(r)
	request = access.NormalizeAccessUserRequest(request)
	if errResponse := ownership.NewService(server.db, server.stmts).RequireOwnershipControl(caller, request.ResourcePath); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	var response *access.AccessUserResponse
	if errResponse := epoch.Transactify(server.db, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		var txErr *coreauthz.ErrorResponse
		response, txErr = access.RevokeUserAccess(tx, request, authzProvider)
		if txErr != nil {
			return txErr
		}
		if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
			return errResponse
		}
		if errResponse := epoch.BumpResourceAuthzEpochTx(tx, request.ResourcePath); errResponse != nil {
			return errResponse
		}
		return epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeUser, request.Username)
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(response, http.StatusOK).write(w, r)
}
