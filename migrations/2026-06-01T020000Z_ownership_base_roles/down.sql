UPDATE db_version SET (id, version) = (7, '2026-06-01T010000Z_owner_bindings_unprotected');

DELETE FROM permission
USING role
WHERE permission.role_id = role.id
AND (
    (
        role.name = 'owner'
        AND permission.name IN (
            'owner_read',
            'owner_create',
            'owner_update',
            'owner_delete',
            'owner_write_storage',
            'owner_read_storage',
            'owner_create_descendant',
            'owner_manage_owners'
        )
    )
    OR (
        role.name = 'org-member'
        AND permission.name = 'org_member_create_descendant'
    )
);
