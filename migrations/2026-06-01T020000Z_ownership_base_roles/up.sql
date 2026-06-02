UPDATE db_version SET (id, version) = (8, '2026-06-01T020000Z_ownership_base_roles');

INSERT INTO role(name, description)
VALUES ('owner', 'Generated owner role')
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description;

INSERT INTO role(name, description)
VALUES ('org-member', 'Generated organization member role')
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description;

INSERT INTO permission(role_id, name, service, method)
VALUES
    ((SELECT id FROM role WHERE name = 'owner'), 'owner_read', '*', 'read'),
    ((SELECT id FROM role WHERE name = 'owner'), 'owner_create', '*', 'create'),
    ((SELECT id FROM role WHERE name = 'owner'), 'owner_update', '*', 'update'),
    ((SELECT id FROM role WHERE name = 'owner'), 'owner_write_storage', '*', 'write-storage'),
    ((SELECT id FROM role WHERE name = 'owner'), 'owner_read_storage', '*', 'read-storage'),
    ((SELECT id FROM role WHERE name = 'owner'), 'owner_create_descendant', 'arborist', 'create-descendant'),
    ((SELECT id FROM role WHERE name = 'owner'), 'owner_manage_owners', 'arborist', 'manage-owners'),
    ((SELECT id FROM role WHERE name = 'org-member'), 'org_member_create_descendant', 'arborist', 'create-descendant')
ON CONFLICT (role_id, name) DO NOTHING;
