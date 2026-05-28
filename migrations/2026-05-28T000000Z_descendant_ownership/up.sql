UPDATE db_version SET (id, version) = (4, '2026-05-28T000000Z_descendant_ownership');

CREATE TABLE ownership_template (
    name VARCHAR PRIMARY KEY,
    description VARCHAR,
    parent_path_pattern VARCHAR NOT NULL,
    child_kind VARCHAR NOT NULL,
    child_container_name VARCHAR,
    owner_role VARCHAR NOT NULL,
    admin_role VARCHAR NOT NULL DEFAULT 'administrator',
    default_admin_groups VARCHAR[] NOT NULL DEFAULT '{}',
    delegable_roles VARCHAR[] NOT NULL DEFAULT '{}'
);

CREATE TABLE generated_policy_metadata (
    policy_id INTEGER PRIMARY KEY REFERENCES policy(id) ON DELETE CASCADE,
    resource_id INTEGER NOT NULL REFERENCES resource(id) ON DELETE CASCADE,
    template_name VARCHAR NOT NULL REFERENCES ownership_template(name),
    kind VARCHAR NOT NULL,
    protected BOOLEAN NOT NULL DEFAULT FALSE,
    created_by VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    provenance JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE ownership_binding_metadata (
    subject_type VARCHAR NOT NULL,
    subject_name VARCHAR NOT NULL,
    policy_id INTEGER NOT NULL REFERENCES policy(id) ON DELETE CASCADE,
    resource_id INTEGER NOT NULL REFERENCES resource(id) ON DELETE CASCADE,
    template_name VARCHAR NOT NULL REFERENCES ownership_template(name),
    kind VARCHAR NOT NULL,
    protected BOOLEAN NOT NULL DEFAULT FALSE,
    created_by VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    provenance JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (subject_type, subject_name, policy_id)
);

INSERT INTO ownership_template (
    name,
    description,
    parent_path_pattern,
    child_kind,
    child_container_name,
    owner_role,
    admin_role,
    default_admin_groups,
    delegable_roles
) VALUES
(
    'gen3-program',
    'Create a Gen3 program under /programs and grant creator ownership.',
    '^/programs$',
    'program',
    'projects',
    'owner',
    'administrator',
    ARRAY['administrators'],
    ARRAY['owner', 'reader', 'writer']
),
(
    'gen3-project',
    'Create a Gen3 project under /programs/<program>/projects and grant creator ownership.',
    '^/programs/[^/]+/projects$',
    'project',
    NULL,
    'owner',
    'administrator',
    ARRAY['administrators'],
    ARRAY['owner', 'reader', 'writer']
);
