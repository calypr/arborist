package engine

import (
	"errors"
	"strings"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/lib/pq"
)

func authorizeAnonymous(request *AuthRequest) (*AuthResponse, error) {
	var tag string
	var err error

	resource := request.Resource
	// See if the resource field is a path or a tag.
	if strings.HasPrefix(resource, "/") {
		resource = coreauthz.FormatPathForDb(resource)
	} else {
		tag = resource
		resource = ""
	}

	var authorized []bool

	if resource != "" {
		// run authorization query
		err = request.stmts.Select(
			`
			SELECT coalesce(text2ltree($5) <@ allowed, FALSE) FROM (
				SELECT array_agg(resource.path) AS allowed FROM (
					SELECT policy_id FROM grp_policy
					INNER JOIN grp ON grp_policy.grp_id = grp.id
					WHERE grp.name = $6
				) AS policies
				LEFT JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
				LEFT JOIN resource ON resource.id = policy_resource.resource_id
				WHERE EXISTS (
					SELECT 1 FROM policy_role
					JOIN permission ON permission.role_id = policy_role.role_id
					WHERE policy_role.policy_id = policies.policy_id
					AND (permission.service = $1 OR permission.service = '*')
					AND (permission.method = $2 OR permission.method = '*')
				) AND (
					$3 OR policies.policy_id IN (
						SELECT id FROM policy
						WHERE policy.name = ANY($4)
					)
				)
			) _
			`,
			&authorized,
			request.Service,            // $1
			request.Method,             // $2
			len(request.Policies) == 0, // $3
			pq.Array(request.Policies), // $4
			resource,                   // $5
			coreauthz.AnonymousGroup,   // $6
		)
	} else if tag != "" {
		err = request.stmts.Select(
			`
			SELECT coalesce((SELECT resource.path AS request FROM resource WHERE resource.tag = $5) <@ allowed, FALSE) FROM (
				SELECT array_agg(resource.path) AS allowed FROM (
					SELECT policy_id FROM grp_policy
					INNER JOIN grp ON grp_policy.grp_id = grp.id
					WHERE grp.name = $6
				) AS policies
				JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
				JOIN resource ON resource.id = policy_resource.resource_id
				WHERE EXISTS (
					SELECT 1 FROM policy_role
					JOIN permission ON permission.role_id = policy_role.role_id
					WHERE policy_role.policy_id = policies.policy_id
					AND (permission.service = $1 OR permission.service = '*')
					AND (permission.method = $2 OR permission.method = '*')
				) AND (
					$3 OR policies.policy_id IN (
						SELECT id FROM policy
						WHERE policy.name = ANY($4)
					)
				)
			) _
			`,
			&authorized,
			request.Service,            // $1
			request.Method,             // $2
			len(request.Policies) == 0, // $3
			pq.Array(request.Policies), // $4
			resource,                   // $5
			coreauthz.AnonymousGroup,   // $6
		)
	} else {
		err = errors.New("missing resource in auth request")
	}
	if err != nil {
		return nil, err
	}
	result := len(authorized) > 0 && authorized[0]
	return &AuthResponse{result}, nil
}

func AuthorizeAnonymous(request *AuthRequest) (*AuthResponse, error) {
	return authorizeAnonymous(request)
}

// Authorize the given token to access resources by service and method.
func authorizeUser(request *AuthRequest) (*AuthResponse, error) {
	var authorized []bool
	var tag string
	var err error

	resource := request.Resource
	// See if the resource field is a path or a tag.
	if strings.HasPrefix(resource, "/") {
		resource = coreauthz.FormatPathForDb(resource)
	} else {
		tag = resource
		resource = ""
	}

	if resource != "" {
		err = request.stmts.Select(
			`
			SELECT coalesce(text2ltree($6) <@ allowed, FALSE) FROM (
				SELECT array_agg(resource.path) AS allowed FROM (
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
					WHERE grp.name IN ($7, $8)
				) AS policies
				JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
				JOIN resource ON resource.id = policy_resource.resource_id
				WHERE EXISTS (
					SELECT 1 FROM policy_role
					JOIN permission ON permission.role_id = policy_role.role_id
					WHERE policy_role.policy_id = policies.policy_id
					AND (permission.service = $2 OR permission.service = '*')
					AND (permission.method = $3 OR permission.method = '*')
				) AND (
					$4 OR policies.policy_id IN (
						SELECT id FROM policy
						WHERE policy.name = ANY($5)
					)
				)
			) _
			`,
			&authorized,
			strings.ToLower(request.Username), // $1
			request.Service,                   // $2
			request.Method,                    // $3
			len(request.Policies) == 0,        // $4
			pq.Array(request.Policies),        // $5
			resource,                          // $6
			coreauthz.AnonymousGroup,          // $7
			coreauthz.LoggedInGroup,           // $8
		)
	} else if tag != "" {
		err = request.stmts.Select(
			`
			SELECT coalesce((SELECT resource.path FROM resource WHERE resource.tag = $6) <@ allowed, FALSE) FROM (
				SELECT array_agg(resource.path) AS allowed FROM (
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
					WHERE grp.name IN ($7, $8)
				) AS policies
				JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
				JOIN resource ON resource.id = policy_resource.resource_id
				WHERE EXISTS (
					SELECT 1 FROM policy_role
					JOIN permission ON permission.role_id = policy_role.role_id
					WHERE policy_role.policy_id = policies.policy_id
					AND (permission.service = $2 OR permission.service = '*')
					AND (permission.method = $3 OR permission.method = '*')
				) AND (
					$4 OR policies.policy_id IN (
						SELECT id FROM policy
						WHERE policy.name = ANY($5)
					)
				)
			) _
			`,
			&authorized,
			strings.ToLower(request.Username), // $1
			request.Service,                   // $2
			request.Method,                    // $3
			len(request.Policies) == 0,        // $4
			pq.Array(request.Policies),        // $5
			tag,                               // $6
			coreauthz.AnonymousGroup,          // $7
			coreauthz.LoggedInGroup,           // $8
		)
	} else {
		err = errors.New("missing resource in auth request")
	}
	if err != nil {
		return nil, err
	}
	result := len(authorized) > 0 && authorized[0]
	return &AuthResponse{result}, nil
}

func AuthorizeUser(request *AuthRequest) (*AuthResponse, error) {
	return authorizeUser(request)
}

// This is similar to authorizeUser, only that this method checks for clientID only
func authorizeClient(request *AuthRequest) (*AuthResponse, error) {
	var err error
	var tag string
	var authorized []bool

	resource := request.Resource
	// See if the resource field is a path or a tag.
	if strings.HasPrefix(resource, "/") {
		resource = coreauthz.FormatPathForDb(resource)
	} else {
		tag = resource
		resource = ""
	}

	if resource != "" {
		err = request.stmts.Select(
			`
			SELECT coalesce(text2ltree($4) <@ allowed, FALSE) FROM (
				SELECT array_agg(resource.path) AS allowed FROM client
				JOIN client_policy ON client_policy.client_id = client.id
				JOIN policy_resource ON policy_resource.policy_id = client_policy.policy_id
				JOIN resource ON resource.id = policy_resource.resource_id
				WHERE client.external_client_id = $1
				AND EXISTS (
					SELECT 1 FROM policy_role
					JOIN permission ON permission.role_id = policy_role.role_id
					WHERE policy_role.policy_id = client_policy.policy_id
					AND (permission.service = $2 OR permission.service = '*')
					AND (permission.method = $3 OR permission.method = '*')
				)
			) _
			`,
			&authorized,
			request.ClientID, // $1
			request.Service,  // $2
			request.Method,   // $3
			resource,         // $4
		)
	} else if tag != "" {
		err = request.stmts.Select(
			`
			SELECT coalesce((SELECT resource.path FROM resource WHERE resource.tag = $6) <@ allowed, FALSE) FROM (
				SELECT array_agg(resource.path) AS allowed FROM (
					SELECT client_policy.policy_id FROM client
					INNER JOIN client_policy ON client_policy.client_id = client.id
					WHERE client.external_client_id = $1
				) AS policies
				JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
				JOIN resource ON resource.id = policy_resource.resource_id
				WHERE EXISTS (
					SELECT 1 FROM policy_role
					JOIN permission ON permission.role_id = policy_role.role_id
					WHERE policy_role.policy_id = policies.policy_id
					AND (permission.service = $2 OR permission.service = '*')
					AND (permission.method = $3 OR permission.method = '*')
				) AND (
					$4 OR policies.policy_id IN (
						SELECT id FROM policy
						WHERE policy.name = ANY($5)
					)
				)
			) _
			`,
			&authorized,
			request.ClientID,           // $1
			request.Service,            // $2
			request.Method,             // $3
			len(request.Policies) == 0, // $4
			pq.Array(request.Policies), // $5
			tag,                        // $6
		)
	} else {
		err = errors.New("missing resource in auth request")
	}
	if err != nil {
		return nil, err
	}
	result := len(authorized) > 0 && authorized[0]
	return &AuthResponse{result}, nil
}

func AuthorizeClient(request *AuthRequest) (*AuthResponse, error) {
	return authorizeClient(request)
}
