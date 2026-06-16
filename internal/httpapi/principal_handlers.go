package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/calypr/arborist/internal/authz/engine"
	"github.com/calypr/arborist/internal/authz/epoch"
	principalstore "github.com/calypr/arborist/internal/authz/store/principal"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
)

type RequestPolicy struct {
	PolicyName string `json:"policy"`
	ExpiresAt  string `json:"expires_at"`
}

func (server *Server) handleUserList(w http.ResponseWriter, r *http.Request) {
	usersFromQuery, err := principalstore.ListUsersFromDb(server.db)
	if err != nil {
		msg := fmt.Sprintf("users query failed: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 500, nil)
		server.writeError(w, r, errResponse)
		return
	}
	users := []principalstore.User{}
	for _, userFromQuery := range usersFromQuery {
		users = append(users, userFromQuery.Standardize())
	}
	result := struct {
		Users []principalstore.User `json:"users"`
	}{Users: users}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handleUserCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	user := &principalstore.User{}
	err := json.Unmarshal(body, user)
	if err != nil {
		msg := fmt.Sprintf("could not parse user from JSON: %s", err.Error())
		server.logger.Info("tried to create user but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}
	errResponse := user.CreateInDb(server.db)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	server.logger.Info("created user %s", user.Name)
	created := struct {
		Created *principalstore.User `json:"created"`
	}{Created: user}
	_ = jsonResponseFrom(created, 201).write(w, r)
}

func (server *Server) handleUserRead(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["username"]
	userFromQuery, err := principalstore.UserWithName(server.db, name)
	if err != nil {
		msg := fmt.Sprintf("user query failed: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 500, nil)
		server.writeError(w, r, errResponse)
		return
	}
	if userFromQuery == nil {
		msg := fmt.Sprintf("no user found with username: %s", name)
		errResponse := coreauthz.NewErrorResponse(msg, 404, nil)
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(userFromQuery.Standardize(), http.StatusOK).write(w, r)
}

func (server *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request, body []byte) {
	name := mux.Vars(r)["username"]
	user := principalstore.User{Name: name}

	userWithScalars := &principalstore.UserWithScalars{}
	err := json.Unmarshal(body, userWithScalars)
	if err != nil {
		msg := fmt.Sprintf("could not coreauthz.Unmarshal body: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, errResponse)
		return
	}

	if userWithScalars.Name == nil && userWithScalars.Email == nil {
		msg := `body must contain at least one valid field. possible valid fields are "name" and "email"`
		errResponse := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, errResponse)
		return
	}

	errResponse := user.UpdateInDb(server.db, userWithScalars.Name, userWithScalars.Email)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	server.logger.Info("updated user %s", user.Name)
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["username"]
	user := principalstore.User{Name: name}
	errResponse := user.DeleteInDb(server.db)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	server.logger.Info("deleted user %s", name)
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) userGrantPolicy(w http.ResponseWriter, r *http.Request, requestPolicy RequestPolicy, username string) {
	var expiresAt *time.Time
	if requestPolicy.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, requestPolicy.ExpiresAt)
		if err != nil {
			msg := "could not parse `expires_at` (must be in RFC 3339 format; see specification: https://tools.ietf.org/html/rfc3339#section-5.8)"
			server.logger.Info("tried to grant policy to user but `expires_at` was invalid format")
			response := coreauthz.NewErrorResponse(msg, 400, nil)
			server.writeError(w, r, response)
			return
		}
		expiresAt = &exp
	}
	errResponse := principalstore.GrantUserPolicy(server.db, username, requestPolicy.PolicyName, expiresAt, getAuthZProvider(r))
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	server.logger.Info("granted policy %s to user %s", requestPolicy.PolicyName, username)
}

func (server *Server) handleUserGrantPolicy(w http.ResponseWriter, r *http.Request, body []byte) {
	username := mux.Vars(r)["username"]
	requestPolicy := &RequestPolicy{}
	err := json.Unmarshal(body, &requestPolicy)
	if err != nil {
		msg := fmt.Sprintf("could not parse policy name in JSON: %s", err.Error())
		server.logger.Info("tried to grant policy to user but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}
	server.userGrantPolicy(w, r, *requestPolicy, username)
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleBulkUserGrantPolicy(w http.ResponseWriter, r *http.Request, body []byte) {
	username := mux.Vars(r)["username"]
	var requestPolicies []RequestPolicy
	err := json.Unmarshal(body, &requestPolicies)
	if err != nil {
		msg := fmt.Sprintf("could not parse policy name in JSON: %s", err.Error())
		server.logger.Info("tried to grant policy to user but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}
	for _, requestPolicy := range requestPolicies {
		server.userGrantPolicy(w, r, requestPolicy, username)
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleUserRevokeAll(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	authzProvider := getAuthZProvider(r)
	errResponse := principalstore.RevokeUserPolicyAll(server.db, username, authzProvider)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if authzProvider.Valid {
		server.logger.Info("revoked all %s policies for user %s", authzProvider.String, username)
	} else {
		server.logger.Info("revoked all policies for user %s", username)
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleUserRevokePolicy(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	policyName := mux.Vars(r)["policyName"]
	authzProvider := getAuthZProvider(r)
	policyInfo, err := principalstore.FetchUserPolicyInfo(server.db, username, policyName)
	if err != nil {
		server.logger.Info("Error Fetching policy Info: %s", err.Error())
		msg := fmt.Sprintf("Error Fetching policy Info: %s", err.Error())
		response := coreauthz.NewErrorResponse(msg, http.StatusInternalServerError, nil)
		server.writeError(w, r, response)
		return
	}

	if policyInfo != nil {
		dbAuthzProvider := ""
		providerExists := policyInfo.AuthzProvider.Valid
		if providerExists {
			dbAuthzProvider = policyInfo.AuthzProvider.String
		}
		server.logger.Debug("store.Policy - {name: %s, authz_provider: %s, expires_at: %s} assigned to user %s",
			policyInfo.PolicyName, dbAuthzProvider, policyInfo.ExpiresAt, policyInfo.Username)

		if !authzProvider.Valid || (providerExists && dbAuthzProvider == authzProvider.String) {
			errResponse := principalstore.RevokeUserPolicy(server.db, username, policyName, authzProvider)
			if errResponse != nil {
				server.writeError(w, r, errResponse)
				return
			}
			server.logger.Info("revoked policy %s for user %s", policyName, username)
			_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
		} else {
			server.logger.Info("Cannot revoke policy `%s`. store.Policy authz_provider `%s` and request authz_provider `%s` mismatch",
				policyName, policyInfo.AuthzProvider.String, authzProvider.String)
			msg := fmt.Sprintf("Cannot revoke policy `%s`. Authz_provider Mismatch", policyName)
			errResponse := coreauthz.NewErrorResponse(msg, http.StatusUnauthorized, nil)
			server.writeError(w, r, errResponse)
		}
	} else {
		msg := fmt.Sprintf("store.Policy `%s` does not exist for user `%s`: not revoking. Check if it is assigned through a group.", policyName, username)
		server.logger.Info("%s", msg)
		_ = jsonResponseFrom(msg, http.StatusBadRequest).write(w, r)
	}
}

func (server *Server) handleUserListResources(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	user, err := principalstore.UserWithName(server.db, username)
	if user == nil || err != nil {
		msg := fmt.Sprintf("no user found with username: `%s`", username)
		errResponse := coreauthz.NewErrorResponse(msg, 404, nil)
		server.writeError(w, r, errResponse)
		return
	}
	service := ""
	serviceQS, ok := r.URL.Query()["service"]
	if ok {
		service = serviceQS[0]
	}
	method := ""
	methodQS, ok := r.URL.Query()["method"]
	if ok {
		method = methodQS[0]
	}
	request := &engine.AuthRequest{Username: username, Service: service, Method: method}
	resourcesFromQuery, errResponse := engine.AuthorizedResources(server.db, request)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	useTags := false
	_, ok = r.URL.Query()["tags"]
	if ok {
		useTags = true
	}
	resources := make([]string, len(resourcesFromQuery))
	for i := range resourcesFromQuery {
		if useTags {
			resources[i] = resourcesFromQuery[i].Tag
		} else {
			resources[i] = resourcesFromQuery[i].Standardize().Path
		}
	}
	result := struct {
		Resources []string `json:"resources"`
	}{Resources: resources}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handleClientList(w http.ResponseWriter, r *http.Request) {
	clientsFromQuery, err := principalstore.ListClientsFromDb(server.db)
	if err != nil {
		msg := fmt.Sprintf("clients query failed: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 500, nil)
		server.writeError(w, r, errResponse)
		return
	}
	clients := []principalstore.Client{}
	for _, clientFromQuery := range clientsFromQuery {
		clients = append(clients, clientFromQuery.Standardize())
	}
	result := struct {
		Clients []principalstore.Client `json:"clients"`
	}{Clients: clients}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handleClientCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	client := &principalstore.Client{}
	err := json.Unmarshal(body, client)
	if err != nil {
		msg := fmt.Sprintf("could not parse client from JSON: %s", err.Error())
		server.logger.Info("tried to create client but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}
	errResponse := client.CreateInDb(server.db, getAuthZProvider(r))
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	created := struct {
		Created *principalstore.Client `json:"created"`
	}{Created: client}
	_ = jsonResponseFrom(created, 201).write(w, r)
}

func (server *Server) handleClientRead(w http.ResponseWriter, r *http.Request) {
	clientID := mux.Vars(r)["clientID"]
	clientFromQuery, err := principalstore.ClientWithClientID(server.db, clientID)
	if clientFromQuery == nil {
		msg := fmt.Sprintf("no client found with clientID: %s", clientID)
		errResponse := coreauthz.NewErrorResponse(msg, 404, nil)
		server.writeError(w, r, errResponse)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("client query failed: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 500, nil)
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(clientFromQuery.Standardize(), http.StatusOK).write(w, r)
}

func (server *Server) handleClientDelete(w http.ResponseWriter, r *http.Request) {
	clientID := mux.Vars(r)["clientID"]
	client := principalstore.Client{ClientID: clientID}
	errResponse := client.DeleteInDb(server.db)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleClientGrantPolicy(w http.ResponseWriter, r *http.Request, body []byte) {
	clientID := mux.Vars(r)["clientID"]
	requestPolicy := struct {
		PolicyName string `json:"policy"`
	}{}
	err := json.Unmarshal(body, &requestPolicy)
	if err != nil {
		msg := fmt.Sprintf("could not parse policy name in JSON: %s", err.Error())
		server.logger.Info("tried to grant policy to client but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}
	server.logger.Info("attempting to grant policy %s to client %s", requestPolicy.PolicyName, clientID)
	errResponse := principalstore.GrantClientPolicy(server.db, clientID, requestPolicy.PolicyName, getAuthZProvider(r))
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleClientRevokeAll(w http.ResponseWriter, r *http.Request) {
	clientID := mux.Vars(r)["clientID"]
	errResponse := principalstore.RevokeClientPolicyAll(server.db, clientID, getAuthZProvider(r))
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleClientRevokePolicy(w http.ResponseWriter, r *http.Request) {
	clientID := mux.Vars(r)["clientID"]
	policyName := mux.Vars(r)["policyName"]
	errResponse := principalstore.RevokeClientPolicy(server.db, clientID, policyName, getAuthZProvider(r))
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleGroupList(w http.ResponseWriter, r *http.Request) {
	groupsFromQuery, err := principalstore.ListGroupsFromDb(server.db)
	if err != nil {
		msg := fmt.Sprintf("groups query failed: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 500, nil)
		server.writeError(w, r, errResponse)
		return
	}
	groups := []principalstore.Group{}
	for _, groupFromQuery := range groupsFromQuery {
		groups = append(groups, groupFromQuery.Standardize())
	}
	result := struct {
		Groups []principalstore.Group `json:"groups"`
	}{Groups: groups}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handleGroupCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	group := &principalstore.Group{}
	err := json.Unmarshal(body, group)
	if err != nil {
		msg := fmt.Sprintf("could not parse group from JSON: %s", err.Error())
		server.logger.Info("tried to create group but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}
	authzProvider := getAuthZProvider(r)
	errResponse := epoch.Transactify(server.db, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		if r.Method == "PUT" {
			return group.OverwriteInDb(tx, authzProvider)
		}
		return group.CreateInDb(tx, authzProvider)
	})
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := epoch.Transactify(server.db, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
			return errResponse
		}
		return epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeGroup, group.Name)
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if r.Method == "PUT" {
		server.logger.Info("overwrote group %s", group.Name)
	} else {
		server.logger.Info("created group %s", group.Name)
	}
	created := struct {
		Created *principalstore.Group `json:"created"`
	}{Created: group}
	_ = jsonResponseFrom(created, 201).write(w, r)
}

func (server *Server) handleGroupRead(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["groupName"]
	groupFromQuery, err := principalstore.GroupWithName(server.db, name)
	if groupFromQuery == nil {
		msg := fmt.Sprintf("no group found with name: %s", name)
		errResponse := coreauthz.NewErrorResponse(msg, 404, nil)
		server.writeError(w, r, errResponse)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("group query failed: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 500, nil)
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(groupFromQuery.Standardize(), http.StatusOK).write(w, r)
}

func (server *Server) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	groupName := mux.Vars(r)["groupName"]
	group := principalstore.Group{Name: groupName}
	errResponse := epoch.Transactify(server.db, group.DeleteInDb)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := epoch.Transactify(server.db, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
			return errResponse
		}
		return epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeGroup, group.Name)
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleGroupAddUser(w http.ResponseWriter, r *http.Request, body []byte) {
	groupName := mux.Vars(r)["groupName"]
	requestUser := struct {
		Username  string `json:"username"`
		ExpiresAt string `json:"expires_at"`
	}{}
	err := json.Unmarshal(body, &requestUser)
	if err != nil {
		msg := fmt.Sprintf("could not parse username in JSON: %s", err.Error())
		server.logger.Info("tried to add user to group but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}
	var expiresAt *time.Time
	if requestUser.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, requestUser.ExpiresAt)
		if err != nil {
			msg := "could not parse `expires_at` (must be in RFC 3339 format; see specification: https://tools.ietf.org/html/rfc3339#section-5.8)"
			server.logger.Info("tried to grant policy to user but `expires_at` was invalid format")
			response := coreauthz.NewErrorResponse(msg, 400, nil)
			server.writeError(w, r, response)
			return
		}
		expiresAt = &exp
	}
	errResponse := principalstore.AddUserToGroup(server.db, requestUser.Username, groupName, expiresAt, getAuthZProvider(r))
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := epoch.Transactify(server.db, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
			return errResponse
		}
		if errResponse := epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeUser, requestUser.Username); errResponse != nil {
			return errResponse
		}
		return epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeGroup, groupName)
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	server.logger.Info("added user %s to group %s", requestUser.Username, groupName)
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleGroupRemoveUser(w http.ResponseWriter, r *http.Request) {
	groupName := mux.Vars(r)["groupName"]
	username := mux.Vars(r)["username"]
	errResponse := principalstore.RemoveUserFromGroup(server.db, username, groupName, getAuthZProvider(r))
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := epoch.Transactify(server.db, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
			return errResponse
		}
		if errResponse := epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeUser, username); errResponse != nil {
			return errResponse
		}
		return epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeGroup, groupName)
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleGroupGrantPolicy(w http.ResponseWriter, r *http.Request, body []byte) {
	groupName := mux.Vars(r)["groupName"]
	requestPolicy := struct {
		PolicyName string `json:"policy"`
	}{}
	err := json.Unmarshal(body, &requestPolicy)
	if err != nil {
		msg := fmt.Sprintf("could not parse policy name in JSON: %s", err.Error())
		server.logger.Info("tried to grant policy to group %s but input was invalid: %s", groupName, msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}
	errResponse := principalstore.GrantGroupPolicy(server.db, groupName, requestPolicy.PolicyName, getAuthZProvider(r))
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := epoch.Transactify(server.db, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
			return errResponse
		}
		return epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeGroup, groupName)
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleGroupRevokePolicy(w http.ResponseWriter, r *http.Request) {
	groupName := mux.Vars(r)["groupName"]
	policyName := mux.Vars(r)["policyName"]
	errResponse := principalstore.RevokeGroupPolicy(server.db, groupName, policyName, getAuthZProvider(r))
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := epoch.Transactify(server.db, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
			return errResponse
		}
		return epoch.BumpSubjectAuthzEpochTx(tx, coreauthz.SubjectTypeGroup, groupName)
	}); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}
