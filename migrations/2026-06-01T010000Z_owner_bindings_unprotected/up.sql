UPDATE db_version SET (id, version) = (7, '2026-06-01T010000Z_owner_bindings_unprotected');

UPDATE generated_policy_metadata
SET protected = FALSE
WHERE kind = 'owner';

UPDATE ownership_binding_metadata
SET protected = FALSE
WHERE kind = 'owner';
