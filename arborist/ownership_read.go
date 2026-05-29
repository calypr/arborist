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
		WITH target_resource AS (
			SELECT id, path
			FROM resource
			WHERE %s
		),
		effective_policy AS (
			SELECT DISTINCT ON (target_resource.id, policy_resource.policy_id)
				target_resource.id AS resource_id,
				target_resource.path AS resource_path,
				policy_resource.policy_id,
				policy_root.path AS policy_resource_path
			FROM target_resource
			JOIN resource AS policy_root ON target_resource.path <@ policy_root.path
			JOIN policy_resource ON policy_resource.resource_id = policy_root.id
			LEFT JOIN generated_policy_metadata ON generated_policy_metadata.policy_id = policy_resource.policy_id
			WHERE generated_policy_metadata.policy_id IS NULL
			ORDER BY target_resource.id, policy_resource.policy_id, nlevel(policy_root.path) DESC
		)
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
		JOIN target_resource ON target_resource.id = resource.id
		UNION ALL
		SELECT
			ltree2text(effective_policy.resource_path) AS resource_path,
			'user' AS subject_type,
			usr.name AS subject_name,
			'direct' AS kind,
			role.name AS role_id,
			policy.name AS policy_id,
			FALSE AS protected,
			'' AS template_name,
			'' AS created_by,
			jsonb_build_object(
				'source', 'arborist-policy',
				'authz_provider', usr_policy.authz_provider,
				'policy_resource_path', ltree2text(effective_policy.policy_resource_path)
			)::jsonb AS provenance
		FROM effective_policy
		JOIN usr_policy ON usr_policy.policy_id = effective_policy.policy_id
		JOIN usr ON usr_policy.usr_id = usr.id
		JOIN policy ON policy.id = effective_policy.policy_id
		JOIN policy_role ON policy_role.policy_id = policy.id
		JOIN role ON role.id = policy_role.role_id
		LEFT JOIN ownership_binding_metadata
			ON ownership_binding_metadata.policy_id = policy.id
			AND ownership_binding_metadata.subject_type = 'user'
			AND LOWER(ownership_binding_metadata.subject_name) = LOWER(usr.name)
		WHERE ownership_binding_metadata.policy_id IS NULL
		AND (usr_policy.expires_at IS NULL OR NOW() < usr_policy.expires_at)
		UNION ALL
		SELECT
			ltree2text(effective_policy.resource_path) AS resource_path,
			'user' AS subject_type,
			usr.name AS subject_name,
			'direct' AS kind,
			role.name AS role_id,
			policy.name AS policy_id,
			FALSE AS protected,
			'' AS template_name,
			'' AS created_by,
			jsonb_build_object(
				'source', 'arborist-group-policy',
				'group', grp.name,
				'membership_authz_provider', usr_grp.authz_provider,
				'policy_authz_provider', grp_policy.authz_provider,
				'policy_resource_path', ltree2text(effective_policy.policy_resource_path)
			)::jsonb AS provenance
		FROM effective_policy
		JOIN grp_policy ON grp_policy.policy_id = effective_policy.policy_id
		JOIN usr_grp ON usr_grp.grp_id = grp_policy.grp_id
		JOIN usr ON usr_grp.usr_id = usr.id
		JOIN grp ON usr_grp.grp_id = grp.id
		JOIN policy ON policy.id = effective_policy.policy_id
		JOIN policy_role ON policy_role.policy_id = policy.id
		JOIN role ON role.id = policy_role.role_id
		LEFT JOIN ownership_binding_metadata
			ON ownership_binding_metadata.policy_id = policy.id
			AND ownership_binding_metadata.subject_type = 'group'
			AND LOWER(ownership_binding_metadata.subject_name) = LOWER(grp.name)
		WHERE ownership_binding_metadata.policy_id IS NULL
		AND (usr_grp.expires_at IS NULL OR NOW() < usr_grp.expires_at)
		UNION ALL
		SELECT
			ltree2text(effective_policy.resource_path) AS resource_path,
			'group' AS subject_type,
			grp.name AS subject_name,
			'direct' AS kind,
			role.name AS role_id,
			policy.name AS policy_id,
			FALSE AS protected,
			'' AS template_name,
			'' AS created_by,
			jsonb_build_object(
				'source', 'arborist-policy',
				'authz_provider', grp_policy.authz_provider,
				'policy_resource_path', ltree2text(effective_policy.policy_resource_path)
			)::jsonb AS provenance
		FROM effective_policy
		JOIN grp_policy ON grp_policy.policy_id = effective_policy.policy_id
		JOIN grp ON grp_policy.grp_id = grp.id
		JOIN policy ON policy.id = effective_policy.policy_id
		JOIN policy_role ON policy_role.policy_id = policy.id
		JOIN role ON role.id = policy_role.role_id
		LEFT JOIN ownership_binding_metadata
			ON ownership_binding_metadata.policy_id = policy.id
			AND ownership_binding_metadata.subject_type = 'group'
			AND LOWER(ownership_binding_metadata.subject_name) = LOWER(grp.name)
		WHERE ownership_binding_metadata.policy_id IS NULL
		ORDER BY resource_path, kind, subject_type, subject_name, role_id
	`, predicate)

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
