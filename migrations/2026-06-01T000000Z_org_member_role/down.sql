UPDATE db_version SET (id, version) = (5, '2026-05-29T000000Z_ownership_read_indexes');

UPDATE ownership_template
SET delegable_roles = array_remove(delegable_roles, 'org-member')
WHERE name = 'gen3-program';

DELETE FROM permission
WHERE name = 'org_member_create_descendant'
AND role_id = (SELECT id FROM role WHERE name = 'org-member');
