UPDATE db_version SET (id, version) = (3, '2019-09-03T155025Z_authz_provider');

DROP TABLE IF EXISTS ownership_binding_metadata;
DROP TABLE IF EXISTS generated_policy_metadata;
DROP TABLE IF EXISTS ownership_template;
