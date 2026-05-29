package arborist

import (
	"encoding/json"
	"fmt"
)

type ownershipResourceReadResponse struct {
	ResourcePath    string                     `json:"resource_path"`
	IncludeChildren bool                       `json:"include_children"`
	Bindings        []ownershipResourceBinding `json:"bindings"`
}

type ownershipResourceBinding struct {
	ResourcePath string                 `json:"resource_path"`
	SubjectType  string                 `json:"subject_type"`
	SubjectName  string                 `json:"subject_name"`
	Kind         string                 `json:"kind"`
	RoleID       string                 `json:"role_id"`
	PolicyID     string                 `json:"policy_id"`
	Protected    bool                   `json:"protected"`
	TemplateName string                 `json:"template_name"`
	CreatedBy    string                 `json:"created_by"`
	Provenance   map[string]interface{} `json:"provenance"`
}

type ownershipResourceBindingRow struct {
	ResourcePath string `db:"resource_path"`
	SubjectType  string `db:"subject_type"`
	SubjectName  string `db:"subject_name"`
	Kind         string `db:"kind"`
	RoleID       string `db:"role_id"`
	PolicyID     string `db:"policy_id"`
	Protected    bool   `db:"protected"`
	TemplateName string `db:"template_name"`
	CreatedBy    string `db:"created_by"`
	Provenance   []byte `db:"provenance"`
}

func (server *Server) readOwnershipResource(resourcePath string, includeChildren bool) (*ownershipResourceReadResponse, *ErrorResponse) {
	predicate := "resource.path = text2ltree($1)"
	if includeChildren {
		predicate = "resource.path <@ text2ltree($1)"
	}

	stmt := fmt.Sprintf(`
		SELECT
			ltree2text(resource.path) AS resource_path,
			ownership_binding_metadata.subject_type,
			ownership_binding_metadata.subject_name,
			ownership_binding_metadata.kind,
			role.name AS role_id,
			policy.name AS policy_id,
			ownership_binding_metadata.protected,
			ownership_binding_metadata.template_name,
			ownership_binding_metadata.created_by,
			ownership_binding_metadata.provenance
		FROM ownership_binding_metadata
		JOIN resource ON ownership_binding_metadata.resource_id = resource.id
		JOIN policy ON ownership_binding_metadata.policy_id = policy.id
		JOIN policy_role ON policy_role.policy_id = policy.id
		JOIN role ON role.id = policy_role.role_id
		WHERE %s
		UNION ALL
		SELECT
			ltree2text(resource.path) AS resource_path,
			'user' AS subject_type,
			usr.name AS subject_name,
			'direct' AS kind,
			role.name AS role_id,
			policy.name AS policy_id,
			FALSE AS protected,
			'' AS template_name,
			'' AS created_by,
			jsonb_build_object('source', 'arborist-policy', 'authz_provider', usr_policy.authz_provider)::jsonb AS provenance
		FROM usr_policy
		JOIN usr ON usr_policy.usr_id = usr.id
		JOIN policy ON usr_policy.policy_id = policy.id
		JOIN policy_resource ON policy_resource.policy_id = policy.id
		JOIN resource ON policy_resource.resource_id = resource.id
		JOIN policy_role ON policy_role.policy_id = policy.id
		JOIN role ON role.id = policy_role.role_id
		LEFT JOIN ownership_binding_metadata
			ON ownership_binding_metadata.policy_id = policy.id
			AND ownership_binding_metadata.resource_id = resource.id
			AND ownership_binding_metadata.subject_type = 'user'
			AND LOWER(ownership_binding_metadata.subject_name) = LOWER(usr.name)
		WHERE %s
		AND ownership_binding_metadata.policy_id IS NULL
		AND (usr_policy.expires_at IS NULL OR NOW() < usr_policy.expires_at)
		UNION ALL
		SELECT
			ltree2text(resource.path) AS resource_path,
			'group' AS subject_type,
			grp.name AS subject_name,
			'direct' AS kind,
			role.name AS role_id,
			policy.name AS policy_id,
			FALSE AS protected,
			'' AS template_name,
			'' AS created_by,
			jsonb_build_object('source', 'arborist-policy', 'authz_provider', grp_policy.authz_provider)::jsonb AS provenance
		FROM grp_policy
		JOIN grp ON grp_policy.grp_id = grp.id
		JOIN policy ON grp_policy.policy_id = policy.id
		JOIN policy_resource ON policy_resource.policy_id = policy.id
		JOIN resource ON policy_resource.resource_id = resource.id
		JOIN policy_role ON policy_role.policy_id = policy.id
		JOIN role ON role.id = policy_role.role_id
		LEFT JOIN ownership_binding_metadata
			ON ownership_binding_metadata.policy_id = policy.id
			AND ownership_binding_metadata.resource_id = resource.id
			AND ownership_binding_metadata.subject_type = 'group'
			AND LOWER(ownership_binding_metadata.subject_name) = LOWER(grp.name)
		WHERE %s
		AND ownership_binding_metadata.policy_id IS NULL
		ORDER BY resource_path, kind, subject_type, subject_name, role_id
	`, predicate, predicate, predicate)

	rows := []ownershipResourceBindingRow{}
	if err := server.db.Select(&rows, stmt, FormatPathForDb(resourcePath)); err != nil {
		return nil, newErrorResponse(fmt.Sprintf("ownership resource query failed: %s", err.Error()), 500, &err)
	}

	bindings := make([]ownershipResourceBinding, 0, len(rows))
	for _, row := range rows {
		provenance := map[string]interface{}{}
		if len(row.Provenance) > 0 {
			if err := json.Unmarshal(row.Provenance, &provenance); err != nil {
				return nil, newErrorResponse(fmt.Sprintf("ownership provenance parse failed: %s", err.Error()), 500, &err)
			}
		}
		bindings = append(bindings, ownershipResourceBinding{
			ResourcePath: formatDbPath(row.ResourcePath),
			SubjectType:  row.SubjectType,
			SubjectName:  row.SubjectName,
			Kind:         row.Kind,
			RoleID:       row.RoleID,
			PolicyID:     row.PolicyID,
			Protected:    row.Protected,
			TemplateName: row.TemplateName,
			CreatedBy:    row.CreatedBy,
			Provenance:   provenance,
		})
	}

	return &ownershipResourceReadResponse{
		ResourcePath:    resourcePath,
		IncludeChildren: includeChildren,
		Bindings:        bindings,
	}, nil
}
