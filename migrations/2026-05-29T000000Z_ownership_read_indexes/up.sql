UPDATE db_version SET (id, version) = (5, '2026-05-29T000000Z_ownership_read_indexes');

CREATE INDEX IF NOT EXISTS policy_resource_resource_policy_idx ON policy_resource(resource_id, policy_id);
CREATE INDEX IF NOT EXISTS usr_policy_policy_usr_idx ON usr_policy(policy_id, usr_id);
CREATE INDEX IF NOT EXISTS grp_policy_policy_grp_idx ON grp_policy(policy_id, grp_id);
CREATE INDEX IF NOT EXISTS usr_grp_grp_usr_idx ON usr_grp(grp_id, usr_id);
CREATE INDEX IF NOT EXISTS ownership_binding_metadata_policy_subject_idx ON ownership_binding_metadata(policy_id, subject_type, subject_name);
CREATE INDEX IF NOT EXISTS ownership_binding_metadata_resource_idx ON ownership_binding_metadata(resource_id);
