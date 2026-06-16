UPDATE db_version SET (id, version) = (9, '2026-06-02T000000Z_logged_in_program_creator');

INSERT INTO role(name, description)
VALUES ('program-creator', 'Allows logged-in users to create top-level programs')
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description;

INSERT INTO permission(role_id, name, service, method)
VALUES (
    (SELECT id FROM role WHERE name = 'program-creator'),
    'program_creator_create_descendant',
    'arborist',
    'create-descendant'
)
ON CONFLICT (role_id, name) DO NOTHING;

INSERT INTO policy(name, description)
VALUES (
    'logged-in-program-creators',
    'Allows any logged-in user to create a program under /programs'
)
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description;

INSERT INTO policy_role(policy_id, role_id)
VALUES (
    (SELECT id FROM policy WHERE name = 'logged-in-program-creators'),
    (SELECT id FROM role WHERE name = 'program-creator')
)
ON CONFLICT DO NOTHING;

INSERT INTO policy_resource(policy_id, resource_id)
VALUES (
    (SELECT id FROM policy WHERE name = 'logged-in-program-creators'),
    (SELECT id FROM resource WHERE path = text2ltree('programs'))
)
ON CONFLICT DO NOTHING;

INSERT INTO grp_policy(grp_id, policy_id)
VALUES (
    (SELECT id FROM grp WHERE name = 'logged-in'),
    (SELECT id FROM policy WHERE name = 'logged-in-program-creators')
)
ON CONFLICT DO NOTHING;
