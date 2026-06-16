UPDATE db_version SET (id, version) = (8, '2026-06-01T020000Z_ownership_base_roles');

DELETE FROM grp_policy
WHERE grp_id = (SELECT id FROM grp WHERE name = 'logged-in')
AND policy_id = (SELECT id FROM policy WHERE name = 'logged-in-program-creators');

DELETE FROM policy_resource
WHERE policy_id = (SELECT id FROM policy WHERE name = 'logged-in-program-creators')
AND resource_id = (SELECT id FROM resource WHERE path = text2ltree('programs'));

DELETE FROM policy_role
WHERE policy_id = (SELECT id FROM policy WHERE name = 'logged-in-program-creators')
AND role_id = (SELECT id FROM role WHERE name = 'program-creator');

DELETE FROM policy
WHERE name = 'logged-in-program-creators';

DELETE FROM permission
WHERE name = 'program_creator_create_descendant'
AND role_id = (SELECT id FROM role WHERE name = 'program-creator');

DELETE FROM role
WHERE name = 'program-creator';
