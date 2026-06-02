UPDATE db_version SET (id, version) = (10, '2026-06-02T020000Z_owner_delete_permission');

INSERT INTO permission(role_id, name, service, method)
VALUES (
    (SELECT id FROM role WHERE name = 'owner'),
    'owner_delete',
    '*',
    'delete'
)
ON CONFLICT (role_id, name) DO NOTHING;
