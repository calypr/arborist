package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/calypr/arborist/internal/authz/engine"
	resourcestore "github.com/calypr/arborist/internal/authz/store/resource"
)

func (server *Server) handleAuthMappingGET(w http.ResponseWriter, r *http.Request) {
	// Try to get username from the JWT.
	username := ""
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		server.logger.Info("Attempting to get username from jwt...")
		userJWT := strings.TrimPrefix(authHeader, "Bearer ")
		userJWT = strings.TrimPrefix(userJWT, "bearer ")
		scopes := []string{"openid"}
		info, err := server.decodeToken(userJWT, scopes)
		if err != nil {
			msg := fmt.Sprintf("tried to get username from jwt, but jwt decode failed: %s", err.Error())
			server.logger.Info("%s", msg)
			_ = jsonResponseFrom(msg, http.StatusBadRequest).write(w, r)
			return
		}
		server.logger.Info("found username in jwt: %s", info.Username)
		username = strings.ToLower(info.Username)
	}

	usernameProvided := username != ""
	if usernameProvided {
		mappings, errResponse := engine.AuthMappingForUser(server.db, username)
		if errResponse != nil {
			server.writeError(w, r, errResponse)
			return
		}
		_ = jsonResponseFrom(mappings, http.StatusOK).write(w, r)
		return
	}

	mappings, errResponse := engine.AuthMappingForGroups(server.db, coreauthz.AnonymousGroup)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(mappings, http.StatusOK).write(w, r)
}

func (server *Server) handleAuthMappingPOST(w http.ResponseWriter, r *http.Request) {
	var errResponse *coreauthz.ErrorResponse = nil
	requestBody := struct {
		Username string `json:"username"`
		ClientID string `json:"clientID"`
	}{}

	body, err := server.parseJsonBody(w, r)
	if err != nil {
		server.writeError(w, r, err)
		return
	}

	username := ""
	clientID := ""
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		server.logger.Info("Attempting to get username or client ID from jwt...")
		userJWT := strings.TrimPrefix(authHeader, "Bearer ")
		userJWT = strings.TrimPrefix(userJWT, "bearer ")
		scopes := []string{"openid"}
		info, err := server.decodeToken(userJWT, scopes)
		if err != nil {
			msg := fmt.Sprintf("tried to get username/client ID from jwt, but jwt decode failed: %s", err.Error())
			server.logger.Info("%s", msg)
			errResponse = coreauthz.NewErrorResponse(msg, 401, nil)
			server.writeError(w, r, errResponse)
			return
		}

		if info.Username != "" {
			username = info.Username
			server.logger.Info("found username in jwt: %s", username)
		} else if info.ClientID != "" {
			clientID = info.ClientID
			server.logger.Info("found client ID in jwt: %s", clientID)
		} else {
			msg := "invalid token (no username or client ID)"
			server.logger.Error("%s", msg)
			errResponse = coreauthz.NewErrorResponse(msg, 401, nil)
			server.writeError(w, r, errResponse)
			return
		}
	} else if len(body) > 0 {
		server.logger.Info("No jwt provided, checking request body")
		err := json.Unmarshal(body, &requestBody)
		if err != nil {
			msg := fmt.Sprintf("could not parse JSON: %s", err.Error())
			server.logger.Error("tried to handle auth mapping request but input was invalid: %s", msg)
			errResponse = coreauthz.NewErrorResponse(msg, 400, nil)
		} else {
			username = requestBody.Username
			clientID = requestBody.ClientID
			if (username == "") == (clientID == "") {
				msg := "must provide a token or specify exactly one of `username` or `clientID` in the request body"
				server.logger.Info("%s", msg)
				errResponse = coreauthz.NewErrorResponse(msg, 400, nil)
			}
		}
		if errResponse != nil {
			server.writeError(w, r, errResponse)
			return
		}
	} else {
		mappings, errResponse := engine.AuthMappingForGroups(server.db, coreauthz.AnonymousGroup)
		if errResponse != nil {
			server.writeError(w, r, errResponse)
			return
		}
		_ = jsonResponseFrom(mappings, http.StatusOK).write(w, r)
		return
	}

	var mappings engine.AuthMapping
	if clientID != "" {
		mappings, errResponse = engine.AuthMappingForClient(server.db, clientID)
	} else {
		mappings, errResponse = engine.AuthMappingForUser(server.db, username)
	}
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(mappings, http.StatusOK).write(w, r)
}

func (server *Server) handleAuthProxy(w http.ResponseWriter, r *http.Request) {
	authRequest, errResponse := engine.AuthRequestFromGET(server.decodeToken, r)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if authRequest.Resource == "" {
		msg := "auth proxy request missing `resource` argument"
		errResponse = coreauthz.NewErrorResponse(msg, 400, nil)
	}
	if authRequest.Service == "" {
		msg := "auth proxy request missing `service` argument"
		errResponse = coreauthz.NewErrorResponse(msg, 400, nil)
	}
	if authRequest.Method == "" {
		msg := "auth request missing `method` argument"
		errResponse = coreauthz.NewErrorResponse(msg, 400, nil)
	}
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	authRequest = authRequest.WithStmts(server.stmts)
	w.Header().Set("REMOTE_USER", authRequest.Username)

	if (authRequest.Username == "") && (authRequest.ClientID == "") {
		msg := "unauthorized: did not provide a username and/or client ID in request"
		server.writeError(w, r, coreauthz.NewErrorResponse(msg, 403, nil))
		return
	}

	rv := &engine.AuthResponse{}
	rv.Auth = true
	var err error = nil
	if authRequest.Username != "" {
		rv, err = engine.AuthorizeUser(authRequest)
		if err != nil {
			msg := fmt.Sprintf("could not authorize user: %s", err.Error())
			server.logger.Info("tried to handle auth request but input was invalid: %s", msg)
			response := coreauthz.NewErrorResponse(msg, 400, nil)
			server.writeError(w, r, response)
			return
		}
		if rv.Auth {
			server.logger.Debug("user is authorized")
		} else {
			server.logger.Debug("user is unauthorized")
		}
	}
	if rv.Auth && authRequest.ClientID != "" {
		rv, err = engine.AuthorizeClient(authRequest)
		if err != nil {
			msg := fmt.Sprintf("could not authorize client: %s", err.Error())
			server.logger.Info("error during client auth check: %s", msg)
			response := coreauthz.NewErrorResponse(msg, 400, nil)
			server.writeError(w, r, response)
			return
		}
		if rv.Auth {
			server.logger.Debug("client is authorized")
		} else {
			server.logger.Debug("client is unauthorized")
		}
	}
	if !rv.Auth {
		errResponse := coreauthz.NewErrorResponse(
			"Unauthorized: user does not have access to this resource", 403, nil)
		server.writeError(w, r, errResponse)
	}
}

func (server *Server) handleAuthRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	authRequestJSON := &engine.AuthRequestJSON{}
	err := json.Unmarshal(body, authRequestJSON)
	if err != nil {
		msg := fmt.Sprintf("could not parse auth request from JSON: %s", err.Error())
		server.logger.Info("tried to handle auth request but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}

	var scopes []string
	if authRequestJSON.User.Scopes == nil {
		scopes = []string{"openid"}
	} else {
		scopes = make([]string, len(authRequestJSON.User.Scopes))
		copy(scopes, authRequestJSON.User.Scopes)
	}

	var isAnonymous bool
	if authRequestJSON.User.UserId == "" && authRequestJSON.User.Token == "" {
		isAnonymous = true
	} else {
		isAnonymous = false
	}

	var info *coreauthz.TokenInfo
	if !isAnonymous && authRequestJSON.User.Token != "" {
		info, err = server.decodeToken(authRequestJSON.User.Token, scopes)
		if err != nil {
			server.logger.Info("%s", err.Error())
			errResponse := coreauthz.NewErrorResponse(err.Error(), 401, &err)
			server.writeError(w, r, errResponse)
			return
		}
	}
	policies := []string{}
	var username string
	var clientID string
	if info != nil {
		policies = info.Policies
		username = info.Username
		clientID = info.ClientID
	} else {
		username = authRequestJSON.User.UserId
		clientID = ""
	}
	if authRequestJSON.User.Policies != nil {
		policies = authRequestJSON.User.Policies
	}

	requests := []engine.AuthRequestJSON_Request{}
	if authRequestJSON.Request != nil {
		requests = append(requests, *authRequestJSON.Request)
	}
	requests = append(requests, authRequestJSON.Requests...)

	if len(requests) == 0 {
		server.writeError(w, r, coreauthz.NewErrorResponse("auth request missing resources", 400, nil))
		return
	}

	for _, authRequest := range requests {
		if isAnonymous {
			request := (&engine.AuthRequest{
				Resource: authRequest.Resource,
				Service:  authRequest.Action.Service,
				Method:   authRequest.Action.Method,
			}).WithStmts(server.stmts)
			rv, err := engine.AuthorizeAnonymous(request)
			if err != nil {
				msg := fmt.Sprintf("could not authorize: %s", err.Error())
				server.logger.Info("tried to handle auth request but input was invalid: %s", msg)
				response := coreauthz.NewErrorResponse(msg, 400, nil)
				server.writeError(w, r, response)
				return
			}
			if !rv.Auth {
				server.logger.Debug("anonymous user is unauthorized")
				_ = jsonResponseFrom(rv, 200).write(w, r)
				return
			}
			continue
		}

		if (clientID == "") && (username == "") && (len(info.Policies) == 0) {
			msg := "missing both username and policies in request (at least one is required when no client ID is provided)"
			server.writeError(w, r, coreauthz.NewErrorResponse(msg, 400, nil))
			return
		}

		if (username == "") && (clientID == "") {
			msg := "unauthorized: did not provide a username and/or client ID in request"
			server.writeError(w, r, coreauthz.NewErrorResponse(msg, 403, nil))
			return
		}

		request := (&engine.AuthRequest{
			Username: username,
			ClientID: clientID,
			Policies: policies,
			Resource: authRequest.Resource,
			Service:  authRequest.Action.Service,
			Method:   authRequest.Action.Method,
		}).WithStmts(server.stmts)
		server.logger.Info("handling auth request: %#v", *request)
		rv := &engine.AuthResponse{}
		rv.Auth = true
		if request.Username != "" {
			rv, err = engine.AuthorizeUser(request)
			if err != nil {
				msg := fmt.Sprintf("could not authorize user: %s", err.Error())
				server.logger.Info("tried to handle auth request but input was invalid: %s", msg)
				response := coreauthz.NewErrorResponse(msg, 400, nil)
				server.writeError(w, r, response)
				return
			}
			if rv.Auth {
				server.logger.Debug("user is authorized")
			} else {
				server.logger.Debug("user is unauthorized")
			}
		}
		if rv.Auth && request.ClientID != "" {
			rv, err = engine.AuthorizeClient(request)
			if err == nil && rv.Auth {
				server.logger.Debug("client is authorized")
			} else {
				server.logger.Debug("client is unauthorized")
			}
			if err != nil {
				msg := fmt.Sprintf("could not authorize client: %s", err.Error())
				server.logger.Info("tried to handle auth request but input was invalid: %s", msg)
				response := coreauthz.NewErrorResponse(msg, 400, nil)
				server.writeError(w, r, response)
				return
			}
		}
		if !rv.Auth {
			_ = jsonResponseFrom(rv, 200).write(w, r)
			return
		}
	}

	result := engine.AuthResponse{Auth: true}
	_ = jsonResponseFrom(result, 200).write(w, r)
}

func (server *Server) handleListAuthResourcesGET(w http.ResponseWriter, r *http.Request) {
	authRequest := &engine.AuthRequest{}
	var errResponse *coreauthz.ErrorResponse
	hasJWT := r.Header.Get("Authorization") != ""
	usernameInJWT := false
	if hasJWT {
		authRequest, errResponse = engine.AuthRequestFromGET(server.decodeToken, r)
		if errResponse != nil {
			server.writeError(w, r, errResponse)
			return
		}
		usernameInJWT = authRequest.Username != ""
	}

	if hasJWT && usernameInJWT {
		authResources, errResponse := engine.AuthorizedResources(server.db, authRequest)
		server.makeAuthResourcesResponse(w, r, authResources, errResponse)
		return
	}

	authResources, errResponse := engine.AuthorizedResourcesForGroups(server.db, coreauthz.AnonymousGroup)
	server.makeAuthResourcesResponse(w, r, authResources, errResponse)
}

func (server *Server) handleListAuthResourcesPOST(w http.ResponseWriter, r *http.Request, body []byte) {
	authRequest := &engine.AuthRequest{}
	var errResponse *coreauthz.ErrorResponse
	request := struct {
		User engine.AuthRequestJSON_User `json:"user"`
	}{}
	err := json.Unmarshal(body, &request)
	if err != nil {
		msg := fmt.Sprintf("could not parse auth request from JSON: %s", err.Error())
		server.logger.Info("tried to handle auth request but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}

	var scopes []string
	if request.User.Scopes == nil {
		scopes = []string{"openid"}
	} else {
		scopes = make([]string, len(request.User.Scopes))
		copy(scopes, request.User.Scopes)
	}

	info, err := server.decodeToken(request.User.Token, scopes)
	if err != nil {
		server.logger.Info("%s", err.Error())
		errResponse := coreauthz.NewErrorResponse(err.Error(), 401, &err)
		server.writeError(w, r, errResponse)
		return
	}

	authRequest.Username = info.Username
	authRequest.ClientID = info.ClientID
	authRequest.Policies = info.Policies
	if request.User.Policies != nil {
		authRequest.Policies = request.User.Policies
	}
	authResources, errResponse := engine.AuthorizedResources(server.db, authRequest)
	server.makeAuthResourcesResponse(w, r, authResources, errResponse)
}

func (server *Server) makeAuthResourcesResponse(w http.ResponseWriter, r *http.Request, resourcesFromQuery []resourcestore.ResourceFromQuery, errResponse *coreauthz.ErrorResponse) {
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}

	resources := []resourcestore.ResourceOut{}
	for _, resourceFromQuery := range resourcesFromQuery {
		resources = append(resources, resourceFromQuery.Standardize())
	}

	useTags := false
	_, ok := r.URL.Query()["tags"]
	if ok {
		useTags = true
	}

	response := struct {
		Resources []string `json:"resources"`
	}{}
	resultList := make([]string, len(resources))
	for i := range resources {
		if useTags {
			resultList[i] = resources[i].Tag
		} else {
			resultList[i] = resources[i].Path
		}
	}
	response.Resources = resultList

	_ = jsonResponseFrom(response, http.StatusOK).write(w, r)
}
