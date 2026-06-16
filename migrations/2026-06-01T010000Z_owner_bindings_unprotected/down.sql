UPDATE db_version SET (id, version) = (6, '2026-06-01T000000Z_org_member_role');

UPDATE generated_policy_metadata
SET protected = TRUE
WHERE kind = 'owner';

UPDATE ownership_binding_metadata
SET protected = TRUE
WHERE kind = 'owner';
