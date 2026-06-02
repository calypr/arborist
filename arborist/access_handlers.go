package arborist

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jmoiron/sqlx"
)

func (server *Server) handleAccessGrantUser(w http.ResponseWriter, r *http.Request, body []byte) {
	var request accessUserRequest
	if err := json.Unmarshal(body, &request); err != nil {
		server.writeError(w, r, newErrorResponse(fmt.Sprintf("could not parse access grant request: %s", err.Error()), 400, nil))
		return
	}
	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	request = normalizeAccessUserRequest(request)
	if errResponse := server.requireOwnershipControl(caller, request.ResourcePath); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	var response *accessUserResponse
	if errResponse := transactify(server.db, func(tx *sqlx.Tx) *ErrorResponse {
		var txErr *ErrorResponse
		response, txErr = grantUserAccess(tx, request, caller)
		return txErr
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(response, http.StatusOK).write(w, r)
}

func (server *Server) handleAccessRevokeUser(w http.ResponseWriter, r *http.Request, body []byte) {
	var request accessUserRequest
	if err := json.Unmarshal(body, &request); err != nil {
		server.writeError(w, r, newErrorResponse(fmt.Sprintf("could not parse access revoke request: %s", err.Error()), 400, nil))
		return
	}
	caller, errResponse := server.usernameFromBearer(r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	request = normalizeAccessUserRequest(request)
	if errResponse := server.requireOwnershipControl(caller, request.ResourcePath); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	var response *accessUserResponse
	if errResponse := transactify(server.db, func(tx *sqlx.Tx) *ErrorResponse {
		var txErr *ErrorResponse
		response, txErr = revokeUserAccess(tx, request)
		return txErr
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(response, http.StatusOK).write(w, r)
}
