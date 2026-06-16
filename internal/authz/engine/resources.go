package engine

import (
	"fmt"
	"net/http"
	"strings"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/calypr/arborist/internal/authz/store/resource"
	"github.com/jmoiron/sqlx"
)

func authRequestFromGET(decode func(string, []string) (*coreauthz.TokenInfo, error), r *http.Request) (*AuthRequest, *coreauthz.ErrorResponse) {
	resourcePath := ""
	resourcePathQS, ok := r.URL.Query()["resource"]
	if ok {
		resourcePath = resourcePathQS[0]
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
	// get JWT from auth header and decode it
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		msg := "auth request missing auth header"
		return nil, coreauthz.NewErrorResponse(msg, 401, nil)
	}
	userJWT := strings.TrimPrefix(authHeader, "Bearer ")
	userJWT = strings.TrimPrefix(userJWT, "bearer ")
	scopes := []string{"openid"}
	info, err := decode(userJWT, scopes)
	if err != nil {
		return nil, coreauthz.NewErrorResponse(err.Error(), 401, &err)
	}

	authRequest := AuthRequest{
		Username: info.Username,
		ClientID: info.ClientID,
		Policies: info.Policies,
		Resource: resourcePath,
		Service:  service,
		Method:   method,
	}

	return &authRequest, nil
}

func AuthRequestFromGET(decode func(string, []string) (*coreauthz.TokenInfo, error), r *http.Request) (*AuthRequest, *coreauthz.ErrorResponse) {
	return authRequestFromGET(decode, r)
}

// authorizedResources returns the resources that are accessible (with any action)
// to the username in AuthRequest. This includes the resources accessible to the
// `anonymous` and `logged-in` groups. If the username in AuthRequest does not exist
// in the db, this this function will NOT throw an error, but will return only
// the resources accessible to the `anonymous` and `logged-in` groups.
//
// See the FIXME inside. Be careful how this is called, until the implementation is updated.
func authorizedResources(db *sqlx.DB, request *AuthRequest) ([]resource.ResourceFromQuery, *coreauthz.ErrorResponse) {
	// if policies are specified in the request, we can use those (simplest query).
	if len(request.Policies) > 0 {
		values := ""
		for _, policy := range request.Policies {
			// FIXME (rudyardrichter, 2019-05-09): this could be a SQL
			// vulnerability if passed arbitrary inputs. As it is this only
			// gets passed the policies from decoded validated tokens.
			values += fmt.Sprintf("('%s'), ", policy)
		}
		values = strings.TrimRight(values, ", ")
		selectPolicyWhereName := fmt.Sprintf(
			"SELECT id FROM policy INNER JOIN (VALUES %s) values(v) ON name = v",
			values,
		)
		stmt := fmt.Sprintf(
			`
			SELECT
				resource.id,
				resource.name,
				resource.path,
				resource.tag,
				resource.description,
				array(
					SELECT child.path
					FROM resource AS child
					WHERE child.path ~ (
						CAST ((ltree2text(resource.path) || '.*{1}') AS lquery)
					)
				) AS subresources
			FROM resource
			INNER JOIN policy_resource ON resource.id = policy_resource.resource_id
			INNER JOIN usr_policy ON usr_policy.policy_id = policy_resource.policy_id
			WHERE (policy_resource.policy_id IN (%s)) AND (
				usr_policy.expires_at IS NULL OR NOW() < usr_policy.expires_at
			)
			`,
			selectPolicyWhereName,
		)
		resources := []resource.ResourceFromQuery{}
		err := db.Select(&resources, stmt)
		if err != nil {
			return nil, coreauthz.NewErrorResponse("resources query (using policies) failed", 500, &err)
		}
		return resources, nil
	}
	resources := []resource.ResourceFromQuery{}
	if request.ClientID == "" {
		if request.Username == "" {
			return nil, coreauthz.NewErrorResponse("missing username in auth request", 400, nil)
		}
		// alternative: SELECT DISTINCT * FROM resource WHERE resource.path <@ ARRAY(SELECT resource.path FROM (SELECT usr_policy.policy_id FROM usr JOIN usr_policy ON usr.id = usr_policy.usr_id WHERE usr.name = $1) policies INNER JOIN policy_resource ON policy_resource.policy_id = policies.policy_id INNER JOIN resource ON resource.id = policy_resource.resource_id);
		stmt := `
			SELECT DISTINCT
				resource.id,
				resource.name,
				resource.path,
				resource.tag,
				resource.description,
				array(
					SELECT child.path
					FROM resource AS child
					WHERE child.path ~ (
						CAST ((ltree2text(resource.path) || '.*{1}') AS lquery)
					)
				) AS subresources
			FROM (
				SELECT usr_policy.policy_id
				FROM usr
				JOIN usr_policy ON usr.id = usr_policy.usr_id
				WHERE LOWER(usr.name) = $1 AND (usr_policy.expires_at IS NULL OR NOW() < usr_policy.expires_at)
				UNION
				SELECT grp_policy.policy_id
				FROM grp
				JOIN grp_policy ON grp_policy.grp_id = grp.id
				JOIN usr_grp ON usr_grp.grp_id = grp.id
				JOIN usr ON usr.id = usr_grp.usr_id
				WHERE LOWER(usr.name) = $1 AND (usr_grp.expires_at IS NULL OR NOW() < usr_grp.expires_at)
				UNION
				SELECT grp_policy.policy_id
				FROM grp
				JOIN grp_policy ON grp_policy.grp_id = grp.id
				WHERE grp.name IN ($2, $3)
			) policies
			INNER JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
			INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
			LEFT JOIN resource ON resource.path <@ roots.path
		`
		err := db.Select(
			&resources,
			stmt,
			strings.ToLower(request.Username), // $1
			coreauthz.AnonymousGroup,          // $2
			coreauthz.LoggedInGroup,           // $3
		)
		if err != nil {
			errResponse := coreauthz.NewErrorResponse(
				"resources query (using username) failed",
				500,
				&err,
			)
			return nil, errResponse
		}
		return resources, nil
	} else {
		stmt := `
			SELECT DISTINCT
				resource.id,
				resource.name,
				resource.path,
				resource.tag,
				resource.description,
				array(
					SELECT child.path
					FROM resource AS child
					WHERE child.path ~ (
						CAST ((ltree2text(resource.path) || '.*{1}') AS lquery)
					)
				) AS subresources
			FROM (
				SELECT usr_policy.policy_id
				FROM usr
				JOIN usr_policy ON usr.id = usr_policy.usr_id
				WHERE LOWER(usr.name) = $1 AND (usr_policy.expires_at IS NULL OR NOW() < usr_policy.expires_at)
				UNION
				SELECT client_policy.policy_id
				FROM client
				JOIN client_policy ON client_policy.client_id = client.id
				WHERE client.external_client_id = $2
				UNION
				SELECT grp_policy.policy_id
				FROM grp
				JOIN grp_policy ON grp_policy.grp_id = grp.id
				JOIN usr_grp ON usr_grp.grp_id = grp.id
				JOIN usr ON usr.id = usr_grp.usr_id
				WHERE LOWER(usr.name) = $1 AND (usr_grp.expires_at IS NULL OR NOW() < usr_grp.expires_at)
			) policies
			LEFT JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
			INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
			LEFT JOIN resource ON resource.path <@ roots.path
		`
		err := db.Select(&resources, stmt, strings.ToLower(request.Username), request.ClientID)
		if err != nil {
			errResponse := coreauthz.NewErrorResponse(
				"resources query (using username + client) failed",
				500,
				&err,
			)
			return nil, errResponse
		}
		return resources, nil
	}
}

func AuthorizedResources(db *sqlx.DB, request *AuthRequest) ([]resource.ResourceFromQuery, *coreauthz.ErrorResponse) {
	return authorizedResources(db, request)
}

// authorizedResourcesForGroups returns the resources that are accessible (with any action)
// to these groups.
func authorizedResourcesForGroups(db *sqlx.DB, groups ...string) ([]resource.ResourceFromQuery, *coreauthz.ErrorResponse) {
	resources := []resource.ResourceFromQuery{}
	stmt := `
		SELECT DISTINCT
			resource.id,
			resource.name,
			resource.path,
			resource.tag,
			resource.description,
			array(
				SELECT child.path
				FROM resource AS child
				WHERE child.path ~ (
					CAST ((ltree2text(resource.path) || '.*{1}') AS lquery)
				)
			) AS subresources
		FROM (
			SELECT grp_policy.policy_id
			FROM grp
			JOIN grp_policy ON grp_policy.grp_id = grp.id
			WHERE grp.name IN (?)
		) policies
		INNER JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
		INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
		LEFT JOIN resource ON resource.path <@ roots.path
	`
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
	err = db.Select(&resources, query, args...)
	if err != nil {
		errResponse := coreauthz.NewErrorResponse(
			"resources query (using no username) failed",
			500,
			&err,
		)
		return nil, errResponse
	}
	return resources, nil
}

func AuthorizedResourcesForGroups(db *sqlx.DB, groups ...string) ([]resource.ResourceFromQuery, *coreauthz.ErrorResponse) {
	return authorizedResourcesForGroups(db, groups...)
}
