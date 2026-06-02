UPDATE db_version SET (id, version) = (9, '2026-06-02T000000Z_logged_in_program_creator');

DELETE FROM permission
WHERE name = 'owner_delete'
AND role_id = (SELECT id FROM role WHERE name = 'owner');
