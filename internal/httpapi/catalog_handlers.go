package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/calypr/arborist/internal/authz/epoch"
	policystore "github.com/calypr/arborist/internal/authz/store/policy"
	resourcestore "github.com/calypr/arborist/internal/authz/store/resource"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
)

func (server *Server) handlePolicyList(w http.ResponseWriter, r *http.Request) {
	_, expandFlag := r.URL.Query()["expand"]
	policiesFromQuery, err := policystore.ListPoliciesFromDb(server.db)
	if err != nil {
		msg := fmt.Sprintf("policies query failed: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 500, nil)
		server.writeError(w, r, errResponse)
		return
	}

	policies := []policystore.Policy{}
	policyOutputs := []policystore.PolicyOut{}
	allPoliciesRoleIDs := []string{}
	for _, policyFromQuery := range policiesFromQuery {
		policy := policyFromQuery.Standardize()
		policies = append(policies, policy)
		policyOutputs = append(policyOutputs, policyFromQuery.StandardizeOut())
		allPoliciesRoleIDs = append(allPoliciesRoleIDs, policy.RoleIDs...)
	}

	expandedPolicies := []policystore.ExpandedPolicy{}
	if expandFlag {
		roleMap := make(map[string]policystore.Role)
		rolesFromQuery, err := policystore.RolesWithNames(server.db, allPoliciesRoleIDs)
		if err != nil {
			msg := fmt.Sprintf("unable to list roles with IDs %v: %s", allPoliciesRoleIDs, err.Error())
			errResponse := coreauthz.NewErrorResponse(msg, 400, nil)
			server.writeError(w, r, errResponse)
			return
		}
		for _, roleFromQuery := range rolesFromQuery {
			role := roleFromQuery.Standardize()
			roleMap[role.Name] = role
		}
		for _, policy := range policies {
			expandedPolicy := policystore.ExpandedPolicy{
				Name:          policy.Name,
				Description:   policy.Description,
				ResourcePaths: policy.ResourcePaths,
			}
			roles := []policystore.Role{}
			for _, roleID := range policy.RoleIDs {
				roles = append(roles, roleMap[roleID])
			}
			expandedPolicy.Roles = roles
			expandedPolicies = append(expandedPolicies, expandedPolicy)
		}
		result := struct {
			Policies []policystore.ExpandedPolicy `json:"policies"`
		}{Policies: expandedPolicies}
		_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
		return
	}

	result := struct {
		Policies []policystore.PolicyOut `json:"policies"`
	}{Policies: policyOutputs}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handlePolicyCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	policy := &policystore.Policy{}
	err := json.Unmarshal(body, policy)
	if err != nil {
		msg := fmt.Sprintf("could not parse policy from JSON: %s", err.Error())
		server.logger.Info("tried to create policy but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}
	errResponse := epoch.Transactify(server.db, policy.CreateInDb)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := epoch.Transactify(server.db, epoch.BumpGlobalAuthzEpochTx); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	server.logger.Info("created policy %s", policy.Name)
	created := struct {
		Created *policystore.Policy `json:"created"`
	}{Created: policy}
	_ = jsonResponseFrom(created, 201).write(w, r)
}

func (server *Server) overwritePolicy(w http.ResponseWriter, r *http.Request, policy policystore.Policy) *coreauthz.ErrorResponse {
	if mux.Vars(r)["policyID"] != "" {
		policy.Name = mux.Vars(r)["policyID"]
	}
	errResponse := epoch.Transactify(server.db, policy.UpdateInDb)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return errResponse
	}
	if errResponse := epoch.Transactify(server.db, epoch.BumpGlobalAuthzEpochTx); errResponse != nil {
		server.writeError(w, r, errResponse)
		return errResponse
	}
	server.logger.Info("overwrote policy %s", policy.Name)
	return nil
}

func (server *Server) handlePolicyOverwrite(w http.ResponseWriter, r *http.Request, body []byte) {
	policy := &policystore.Policy{}
	err := json.Unmarshal(body, policy)
	if err != nil {
		msg := fmt.Sprintf("could not parse policy from JSON: %s", err.Error())
		server.logger.Info("tried to create policy but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}
	errResponse := server.overwritePolicy(w, r, *policy)
	if errResponse != nil {
		return
	}
	updated := struct {
		Updated *policystore.Policy `json:"updated"`
	}{Updated: policy}
	_ = jsonResponseFrom(updated, 201).write(w, r)
}

func (server *Server) handleBulkPoliciesOverwrite(w http.ResponseWriter, r *http.Request, body []byte) {
	var policies []policystore.Policy
	err := json.Unmarshal(body, &policies)
	if err != nil {
		msg := fmt.Sprintf("could not parse policies from JSON: %s", err.Error())
		server.logger.Info("tried to create policies but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}
	for _, policy := range policies {
		server.overwritePolicy(w, r, policy)
	}
	updated := struct {
		Updated []policystore.Policy `json:"updated"`
	}{Updated: policies}
	_ = jsonResponseFrom(updated, 201).write(w, r)
}

func (server *Server) handlePolicyRead(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["policyID"]
	policyFromQuery, err := policystore.PolicyWithName(server.db, name)
	if policyFromQuery == nil {
		msg := fmt.Sprintf("no policy found with id: %s", name)
		errResponse := coreauthz.NewErrorResponse(msg, 404, nil)
		server.writeError(w, r, errResponse)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("policy query failed: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 500, nil)
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(policyFromQuery.StandardizeOut(), http.StatusOK).write(w, r)
}

func (server *Server) handlePolicyDelete(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["policyID"]
	policy := &policystore.Policy{Name: name}
	errResponse := epoch.Transactify(server.db, policy.DeleteInDb)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := epoch.Transactify(server.db, epoch.BumpGlobalAuthzEpochTx); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	server.logger.Info("deleted policy %s", name)
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleResourceList(w http.ResponseWriter, r *http.Request) {
	resourcesFromQuery, err := resourcestore.ListResourcesFromDb(server.db)
	resources := []resourcestore.ResourceOut{}
	for _, resourceFromQuery := range resourcesFromQuery {
		resources = append(resources, resourceFromQuery.Standardize())
	}
	if err != nil {
		msg := fmt.Sprintf("resources query failed: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 500, nil)
		server.writeError(w, r, errResponse)
		return
	}
	result := struct {
		Resources []resourcestore.ResourceOut `json:"resources"`
	}{Resources: resources}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handleResourceCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	resource := &resourcestore.ResourceIn{}
	errResponse := coreauthz.Unmarshal(body, resource)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}

	parentPath := parseResourcePath(r)
	resource.AddPath(parentPath)

	if _, createParentsFlag := r.URL.Query()["p"]; createParentsFlag {
		server.logger.Info("creating parent resources for %s", resource.Path)
		segments := strings.Split(strings.TrimLeft(resource.Path, "/"), "/")
		for i := 0; i < len(segments)-1; i++ {
			path := "/" + strings.Join(segments[:i+1], "/")
			toCreate := resourcestore.ResourceIn{Path: path}
			_ = epoch.Transactify(server.db, toCreate.CreateRecursively)
		}
	}

	errResponse = nil
	if r.Method == "PUT" {
		_, mergeFlag := r.URL.Query()["merge"]
		updateResource := func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
			resource.UpdateInDb(tx, mergeFlag)
			if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
				return errResponse
			}
			return epoch.BumpResourceAuthzEpochTx(tx, resource.Path)
		}
		errResponse = epoch.Transactify(server.db, updateResource)
	} else {
		errResponse = epoch.Transactify(server.db, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
			if errResponse := resource.CreateInDb(tx); errResponse != nil {
				return errResponse
			}
			if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
				return errResponse
			}
			return epoch.BumpResourceAuthzEpochTx(tx, resource.Path)
		})
	}
	if errResponse != nil && errResponse.HTTPError.Code != 409 {
		if errResponse.HTTPError.Code == 500 {
			errResponse.HTTPError.Code = 400
		}
		server.writeError(w, r, errResponse)
		return
	}
	resourceFromQuery, err := resourcestore.ResourceWithPath(server.db, resource.Path)
	if err != nil {
		errResponse := coreauthz.NewErrorResponse(err.Error(), 500, &err)
		server.writeError(w, r, errResponse)
		return
	}
	if resourceFromQuery == nil {
		msg := fmt.Sprintf("couldn't return resource for %s, but it may have been created OK", resource.Path)
		errResponse := coreauthz.NewErrorResponse(msg, 500, &err)
		server.writeError(w, r, errResponse)
		return
	}
	out := resourceFromQuery.Standardize()
	if errResponse != nil {
		server.logger.Info("not creating resource %s (%s), already exists", out.Path, out.Tag)
		result := struct {
			Error  coreauthz.HTTPError         `json:"error"`
			Exists *resourcestore.ResourceOut `json:"exists"`
		}{Error: errResponse.HTTPError, Exists: &out}
		_ = jsonResponseFrom(result, 409).write(w, r)
		return
	}
	server.logger.Info("created resource %s (%s)", out.Path, out.Tag)
	result := struct {
		Created *resourcestore.ResourceOut `json:"created"`
	}{Created: &out}
	_ = jsonResponseFrom(result, 201).write(w, r)
}

func (server *Server) handleResourceRead(w http.ResponseWriter, r *http.Request) {
	path := parseResourcePath(r)
	resourceFromQuery, err := resourcestore.ResourceWithPath(server.db, path)
	if resourceFromQuery == nil {
		msg := fmt.Sprintf("no resource found with path: `%s`", path)
		errResponse := coreauthz.NewErrorResponse(msg, 404, nil)
		server.writeError(w, r, errResponse)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("resource query failed: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 500, nil)
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(resourceFromQuery.Standardize(), http.StatusOK).write(w, r)
}

func (server *Server) handleResourceReadByTag(w http.ResponseWriter, r *http.Request) {
	tag := mux.Vars(r)["tag"]
	resourceFromQuery, err := resourcestore.ResourceWithTag(server.db, tag)
	if resourceFromQuery == nil {
		msg := fmt.Sprintf("no resource found with tag: `%s`", tag)
		errResponse := coreauthz.NewErrorResponse(msg, 404, nil)
		server.writeError(w, r, errResponse)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("resource query failed: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 500, nil)
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(resourceFromQuery.Standardize(), http.StatusOK).write(w, r)
}

func (server *Server) handleResourceDelete(w http.ResponseWriter, r *http.Request) {
	path := parseResourcePath(r)
	resource := resourcestore.ResourceIn{Path: path}
	errResponse := epoch.Transactify(server.db, func(tx *sqlx.Tx) *coreauthz.ErrorResponse {
		if errResponse := resource.DeleteInDb(tx); errResponse != nil {
			return errResponse
		}
		if errResponse := epoch.BumpGlobalAuthzEpochTx(tx); errResponse != nil {
			return errResponse
		}
		return epoch.BumpResourceAuthzEpochTx(tx, resource.Path)
	})
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	server.logger.Info("deleted resource %s", resource.Path)
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleRoleList(w http.ResponseWriter, r *http.Request) {
	rolesFromQuery, err := policystore.ListRolesFromDb(server.db)
	if err != nil {
		msg := fmt.Sprintf("roles query failed: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 500, nil)
		server.writeError(w, r, errResponse)
		return
	}
	roles := []policystore.Role{}
	for _, roleFromQuery := range rolesFromQuery {
		roles = append(roles, roleFromQuery.Standardize())
	}
	result := struct {
		Roles []policystore.Role `json:"roles"`
	}{Roles: roles}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handleRoleCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	role := &policystore.Role{}
	err := json.Unmarshal(body, role)
	if err != nil {
		msg := fmt.Sprintf("could not parse role from JSON: %s", err.Error())
		server.logger.Info("tried to create role but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}
	errResponse := role.CreateInDb(server.db)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := epoch.Transactify(server.db, epoch.BumpGlobalAuthzEpochTx); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	server.logger.Info("created role %s", role.Name)
	created := struct {
		Created *policystore.Role `json:"created"`
	}{Created: role}
	_ = jsonResponseFrom(created, 201).write(w, r)
}

func (server *Server) handleRoleRead(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["roleID"]
	roleFromQuery, err := policystore.RoleWithName(server.db, name)
	if roleFromQuery == nil {
		msg := fmt.Sprintf("no role found with id: %s", name)
		errResponse := coreauthz.NewErrorResponse(msg, 404, nil)
		server.writeError(w, r, errResponse)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("role query failed: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 500, nil)
		server.writeError(w, r, errResponse)
		return
	}
	_ = jsonResponseFrom(roleFromQuery.Standardize(), http.StatusOK).write(w, r)
}

func (server *Server) handleRoleOverwrite(w http.ResponseWriter, r *http.Request, body []byte) {
	role := &policystore.Role{}
	err := json.Unmarshal(body, role)
	if err != nil {
		msg := fmt.Sprintf("could not parse role from JSON: %s", err.Error())
		server.logger.Info("tried to overwrite role but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}
	name := mux.Vars(r)["roleID"]
	if name != role.Name {
		msg := fmt.Sprintf("roleID '%s' from URL did not match roleID '%s' from JSON", name, role.Name)
		server.logger.Info("tried to overwrite role but input was invalid: %s", msg)
		response := coreauthz.NewErrorResponse(msg, 400, nil)
		server.writeError(w, r, response)
		return
	}

	roleFromQuery, err := policystore.RoleWithName(server.db, name)
	if err != nil {
		msg := fmt.Sprintf("role query failed: %s", err.Error())
		errResponse := coreauthz.NewErrorResponse(msg, 500, nil)
		server.writeError(w, r, errResponse)
		return
	}

	if roleFromQuery == nil {
		errResponse := role.CreateInDb(server.db)
		if errResponse != nil {
			server.writeError(w, r, errResponse)
			return
		}
		if errResponse := epoch.Transactify(server.db, epoch.BumpGlobalAuthzEpochTx); errResponse != nil {
			server.writeError(w, r, errResponse)
			return
		}
		server.logger.Info("created role %s", role.Name)
		created := struct {
			Created *policystore.Role `json:"created"`
		}{Created: role}
		_ = jsonResponseFrom(created, 201).write(w, r)
		return
	}

	errResponse := role.OverwriteInDb(server.db)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := epoch.Transactify(server.db, epoch.BumpGlobalAuthzEpochTx); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	server.logger.Info("updated role %s", role.Name)
	updated := struct {
		Updated *policystore.Role `json:"updated"`
	}{Updated: role}
	_ = jsonResponseFrom(updated, 200).write(w, r)
}

func (server *Server) handleRoleDelete(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["roleID"]
	role := &policystore.Role{Name: name}
	errResponse := role.DeleteInDb(server.db)
	if errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	if errResponse := epoch.Transactify(server.db, epoch.BumpGlobalAuthzEpochTx); errResponse != nil {
		server.writeError(w, r, errResponse)
		return
	}
	server.logger.Info("deleted role %s", role.Name)
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}
