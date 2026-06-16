package engine

import (
	"fmt"
	"strings"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/jmoiron/sqlx"
)

type AuthMappingQuery struct {
	Path    string `json:"path"`
	Service string `json:"service"`
	Method  string `json:"method"`
}

type AuthMapping map[string][]coreauthz.Action

// authMappingForUser gets the auth mapping for the user with this username.
// The user's auth mapping includes the permissions of the `anonymous` and
// `logged-in` groups.
// If there is no user with this username in the db, this function will NOT
// throw an error, but will return only the auth mapping of the `anonymous`
// and `logged-in` groups.
func authMappingForUser(db *sqlx.DB, username string) (AuthMapping, *coreauthz.ErrorResponse) {
	mappingQuery := []AuthMappingQuery{}
	stmt := fmt.Sprintf(`
		SELECT DISTINCT resource.path, permission.service, permission.method
		FROM
		(
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
			WHERE grp.name IN ($2, $3)
		) AS policies
		INNER JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
		INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
		INNER JOIN policy_role ON policy_role.policy_id = policies.policy_id
		INNER JOIN permission ON permission.role_id = policy_role.role_id
		INNER JOIN resource ON (
			(
				permission.service = 'arborist'
				AND permission.method = '%s'
				AND resource.path = roots.path
			)
			OR
			(
				NOT (
					permission.service = 'arborist'
					AND permission.method = '%s'
				)
				AND resource.path <@ roots.path
			)
		)
	`, coreauthz.CreateDescendantMethod, coreauthz.CreateDescendantMethod)
	err := db.Select(
		&mappingQuery,
		stmt,
		strings.ToLower(username), // $1
		coreauthz.AnonymousGroup,  // $2
		coreauthz.LoggedInGroup,   // $3
	)
	if err != nil {
		errResponse := coreauthz.NewErrorResponse("mapping query failed", 500, &err)
		errResponse.Log.Error("%s", err.Error())
		return nil, errResponse
	}
	mapping := make(AuthMapping)
	for _, authMap := range mappingQuery {
		path := coreauthz.FormatDbPath(authMap.Path)
		action := coreauthz.Action{Service: authMap.Service, Method: authMap.Method}
		mapping[path] = append(mapping[path], action)
	}
	return mapping, nil
}

func AuthMappingForUser(db *sqlx.DB, username string) (AuthMapping, *coreauthz.ErrorResponse) {
	return authMappingForUser(db, username)
}

// authMappingForGroups returns the auth mapping of resources associated with groups.
func authMappingForGroups(db *sqlx.DB, groups ...string) (AuthMapping, *coreauthz.ErrorResponse) {
	mappingQuery := []AuthMappingQuery{}
	stmt := fmt.Sprintf(`
		SELECT DISTINCT resource.path, permission.service, permission.method
		FROM
		(
			SELECT grp_policy.policy_id FROM grp
			INNER JOIN grp_policy ON grp_policy.grp_id = grp.id
			WHERE grp.name IN (?)
		) AS policies
		INNER JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
		INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
		INNER JOIN policy_role ON policy_role.policy_id = policies.policy_id
		INNER JOIN permission ON permission.role_id = policy_role.role_id
		INNER JOIN resource ON (
			(
				permission.service = 'arborist'
				AND permission.method = '%s'
				AND resource.path = roots.path
			)
			OR
			(
				NOT (
					permission.service = 'arborist'
					AND permission.method = '%s'
				)
				AND resource.path <@ roots.path
			)
		)
	`, coreauthz.CreateDescendantMethod, coreauthz.CreateDescendantMethod)
	// sqlx.In allows safely binding variable numbers of arguments as bindvars.
	// See https://jmoiron.github.io/sqlx/#inQueries,
	query, args, err := sqlx.In(stmt, groups)
	if err != nil {
		errResponse := coreauthz.NewErrorResponse("mapping query failed", 500, &err)
		errResponse.Log.Error("%s", err.Error())
		return nil, errResponse
	}
	// db.Rebind converts the '?' bindvar syntax required by sqlx.In to postgres $1 bindvar syntax
	query = db.Rebind(query)
	err = db.Select(&mappingQuery, query, args...)
	if err != nil {
		errResponse := coreauthz.NewErrorResponse("mapping query failed", 500, &err)
		errResponse.Log.Error("%s", err.Error())
		return nil, errResponse
	}
	mapping := make(AuthMapping)
	for _, authMap := range mappingQuery {
		path := coreauthz.FormatDbPath(authMap.Path)
		action := coreauthz.Action{Service: authMap.Service, Method: authMap.Method}
		mapping[path] = append(mapping[path], action)
	}
	return mapping, nil
}

func AuthMappingForGroups(db *sqlx.DB, groups ...string) (AuthMapping, *coreauthz.ErrorResponse) {
	return authMappingForGroups(db, groups...)
}

// authMappingForClient gets the auth mapping for a client ID.
// It does NOT includes the permissions of the `anonymous` and
// `logged-in` groups.
// If there is no client with this ID in the db, this function will NOT
// throw an error, but will return an empty response.
func authMappingForClient(db *sqlx.DB, clientID string) (AuthMapping, *coreauthz.ErrorResponse) {
	mappingQuery := []AuthMappingQuery{}
	stmt := fmt.Sprintf(`
		SELECT DISTINCT resource.path, permission.service, permission.method
		FROM
		(
			SELECT client_policy.policy_id FROM client
			INNER JOIN client_policy ON client_policy.client_id = client.id
			WHERE client.external_client_id = $1
		) AS policies
		INNER JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
		INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
		INNER JOIN policy_role ON policy_role.policy_id = policies.policy_id
		INNER JOIN permission ON permission.role_id = policy_role.role_id
		INNER JOIN resource ON (
			(
				permission.service = 'arborist'
				AND permission.method = '%s'
				AND resource.path = roots.path
			)
			OR
			(
				NOT (
					permission.service = 'arborist'
					AND permission.method = '%s'
				)
				AND resource.path <@ roots.path
			)
		)
	`, coreauthz.CreateDescendantMethod, coreauthz.CreateDescendantMethod)
	err := db.Select(
		&mappingQuery,
		stmt,
		clientID, // $1
	)
	if err != nil {
		errResponse := coreauthz.NewErrorResponse("mapping query failed", 500, &err)
		errResponse.Log.Error("%s", err.Error())
		return nil, errResponse
	}
	mapping := make(AuthMapping)
	for _, authMap := range mappingQuery {
		path := coreauthz.FormatDbPath(authMap.Path)
		action := coreauthz.Action{Service: authMap.Service, Method: authMap.Method}
		mapping[path] = append(mapping[path], action)
	}
	return mapping, nil
}

func AuthMappingForClient(db *sqlx.DB, clientID string) (AuthMapping, *coreauthz.ErrorResponse) {
	return authMappingForClient(db, clientID)
}
