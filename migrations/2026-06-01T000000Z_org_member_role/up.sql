UPDATE db_version SET (id, version) = (6, '2026-06-01T000000Z_org_member_role');

INSERT INTO role(name, description)
VALUES ('org-member', 'Generated organization member role')
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description;

INSERT INTO permission(role_id, name, service, method)
VALUES (
    (SELECT id FROM role WHERE name = 'org-member'),
    'org_member_create_descendant',
    'arborist',
    'create-descendant'
)
ON CONFLICT (role_id, name) DO NOTHING;

UPDATE ownership_template
SET delegable_roles = array_append(delegable_roles, 'org-member')
WHERE name = 'gen3-program'
AND NOT ('org-member' = ANY(delegable_roles));

INSERT INTO policy_resource(policy_id, resource_id)
SELECT DISTINCT
    ownership_binding_metadata.policy_id,
    child_resource.id
FROM ownership_binding_metadata
JOIN resource AS parent_resource
    ON ownership_binding_metadata.resource_id = parent_resource.id
JOIN ownership_template
    ON ownership_template.name = ownership_binding_metadata.template_name
JOIN resource AS child_resource
    ON child_resource.path = text2ltree(
        ltree2text(parent_resource.path) || '.' || ownership_template.child_container_name
    )
WHERE ownership_binding_metadata.kind = 'owner'
AND ownership_template.child_container_name IS NOT NULL
ON CONFLICT DO NOTHING;
