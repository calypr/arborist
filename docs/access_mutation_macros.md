# Arborist Access Mutation Macros

## Summary

This branch adds a narrow access-mutation layer to Arborist so product clients
can add or remove direct user access without knowing how Arborist currently
represents that access internally.

The public mutation surface is:

- `POST /access/user`
- `DELETE /access/user`

In Gen3 deployments these routes are exposed through revproxy as:

- `POST /authz/access/user`
- `DELETE /authz/access/user`

The macro is intentionally RBAC-shaped. The caller provides a resource path, a
username, and a role id. Arborist decides whether the request maps to a safe
direct user-policy grant or a grant source that must be rejected rather than
guessed at.

The design rule is simple: clients express access intent; Arborist owns graph
classification, mutation safety, and provenance handling.

## Why Arborist Owns This

Arborist is the source of truth for resources, roles, policies, users, groups,
and bindings. It is also the only service that can correctly distinguish these
cases:

- direct legacy user-policy access
- inherited ancestor access
- group-derived access
- protected admin access
- broad policy access that touches multiple roles or resources

The frontend settings page should not encode that distinction. It needs one
operation for direct user access management. If the frontend has to know which
table or policy generated a row, the API boundary is wrong.

Requestor is also not the right place for this logic. Requestor is an
access-request and approval workflow service. These macros are owner/admin
control-plane mutations against Arborist's authorization graph. Moving the
resolver into Requestor would force another service to duplicate Arborist's
storage model and safety rules.

## Relationship To Ownership APIs

The ownership APIs remain the correct API for ownership concepts:

- `/ownership/descendant` creates missing resources and materializes ownership.
- `/ownership/owner` adds or removes resource owners.
- `/ownership/resource` reads ownership and direct-access state for a resource
  tree.

The access macro does not replace owner management. It handles direct
non-owner user access on an existing resource. Owner add/remove must stay on
ownership endpoints because ownership is a separate control-plane concept from
ordinary reader/writer project access.

## API Contract

`POST /access/user` grants direct user access.

`DELETE /access/user` removes direct user access when it is safe to do so.

Both routes accept the same logical fields:

- `resource_path`: absolute Arborist resource path.
- `username`: target user identity.
- `role_id`: configured Arborist role id to grant or remove.

The macro is role-name agnostic. Arborist does not hardcode Calypr product role
labels. The requested role must exist in Arborist and must be allowed by the
resource's ownership template or policy rules for direct delegation. The
frontend is responsible for choosing which configured roles it offers in a
given UI, but Arborist validates the final request.

Responses are structured so callers can distinguish mutation success from safe
rejection:

- `granted`: access binding created or reused by grant calls.
- `removed`: grant entries removed by revoke calls.
- `not_removed`: effective grants Arborist identified but refused to mutate.

Rejected entries include machine-readable reasons. A successful HTTP response
with `not_removed` is not a no-op success; it means Arborist understood the
request and declined unsafe mutation of one or more grant sources.

## Authorization

The caller must be authorized to manage access on the target resource. The
access macro reuses the ownership-control checks already used by owner
management. A caller must be a direct owner with management rights or have an
admin-equivalent permission such as wildcard or manage-owner authority on the
resource.

The authorization check is performed before graph mutation. Unauthorized
callers receive a normal authorization error and no graph inspection result.

## Grant Semantics

Granting access is additive and narrow.

The grant path:

- validates request shape and target identity
- verifies caller management authority
- resolves the resource template and validates the requested role
- creates or reuses a direct policy for exactly the target resource and
  requested role
- returns the resulting direct binding state

The macro does not create missing resources. Missing resource creation remains
the job of `/ownership/descendant`.

The macro does not grant owner status. Ownership remains the job of
`/ownership/owner`.

## Revoke Semantics

Revoking access is conservative.

The revoke path:

- validates request shape and target identity
- verifies caller management authority
- removes matching legacy direct user-policy grants only when the policy is
  exact and narrow
- reports inherited, group-derived, protected, or broad grants as rejected
  instead of modifying them

The endpoint is designed to avoid accidental privilege loss outside the
specific user/resource/role tuple requested by the caller.

## Removable Grants

A grant is removable by the macro when all of these are true:

- it applies directly to the requested user
- it applies exactly to the requested resource
- it grants exactly the requested role
- it is not protected
- it is not admin-derived
- removing it does not require editing group membership
- removing it does not require changing an ancestor resource grant
- removing it does not require splitting a broad multi-resource or multi-role
  policy

Legacy direct user-policy grants are removable only when their policy shape is
exact. Arborist deletes the narrow direct grant rather than trying to infer a
caller-safe rewrite of a broader policy.

## Non-removable Grants

The macro rejects, rather than partially mutates, these grant sources:

- inherited access from an ancestor resource
- group-derived access
- protected admin or recovery access
- owner access
- broad direct policies with multiple resources
- broad direct policies with multiple roles
- grants where deleting the row would affect a different user, role, or
  resource than requested

This is intentional. Splitting broad policies or editing group membership is a
separate administrative operation. It should not be hidden behind a project
settings button.

## Read Path

The settings UI reads from:

- `GET /ownership/resource`

In Gen3 deployments:

- `GET /authz/ownership/resource`

That read endpoint returns ownership-managed rows and direct Arborist policy
rows for the requested resource tree. It is the display source for org owners,
project owners, and direct project access.

`policy_id` may appear in read responses for debugging and operator context.
The normal access mutation UI must not pass `policy_id` for add/remove user
access. The mutation macro intentionally accepts only the RBAC-shaped tuple.

## Frontend Contract

The frontend should use these APIs as follows:

- Use `/authz/ownership/resource` to render current org/project access state.
- Use `/authz/ownership/owner` for org or project owner add/remove.
- Use `/authz/access/user` for direct project role add/remove.
- Do not call raw policy APIs for ordinary access-management UI.
- Do not pass policy ids for ordinary direct access mutation.
- Display `not_removed` reasons when Arborist rejects a broad or inherited
  grant.
- Refetch ownership state after successful mutation calls.

The frontend may present a constrained list of roles for a product workflow.
That list is a UI policy choice, not an Arborist macro assumption. Arborist
still validates `role_id` against configured server-side role/template rules.

## Revproxy Contract

Browser clients should not send raw bearer tokens directly to Arborist.
Revproxy terminates browser session state, performs the normal Gen3 auth
translation, and forwards authenticated proxy headers to Arborist.

The `/authz/access/` block should mirror the `/authz/ownership/` block:

- require CSRF for mutating browser requests
- use the authenticated proxy header include
- rewrite `/authz/access/<path>` to `/access/<path>`
- proxy to `arborist-service`

Arborist expects the deployment's authenticated proxy contract. It should not
carry browser-cookie parsing or Fence session logic internally.

## Safety Invariants

The macro must preserve these invariants:

- No caller can remove protected admin recovery access through access macros.
- No caller can remove inherited access by targeting a descendant row.
- No caller can remove group-derived access by targeting a single user grant.
- No caller can accidentally split or weaken broad policies.
- No caller can mutate owner semantics through direct access APIs.
- Exact direct grants can be removed without needing the frontend to understand
  policy storage details.

## Implementation Notes

Core implementation lives in:

- `internal/access/access.go`
- `internal/httpapi/access_handlers.go`
- `internal/ownership/ownership_bindings.go`
- `internal/ownership/ownership_templates.go`
- `internal/httpapi/ownership_auth.go`

The route registration lives in `internal/httpapi/server.go`.

The access macro keeps ownership-only behavior out of the RBAC-shaped endpoint
and only manages direct user-policy grants.

## Testing Requirements

Server tests should cover:

- grant creates or reuses an exact direct access binding
- grant rejects roles that are not valid for the target resource/template
- revoke removes exact legacy direct user-policy access
- revoke rejects inherited access
- revoke rejects group-derived access
- revoke rejects protected admin access
- revoke rejects broad multi-resource policies
- revoke rejects broad multi-role policies
- unauthorized callers receive authorization errors before mutation
- response bodies distinguish removed and not-removed grants

Frontend/core tests should cover:

- typed hooks call `/authz/access/user`
- add/remove sends resource path, username, and role id
- project settings uses access macros for direct user roles
- owner changes continue to use ownership endpoints
- rejected removals display Arborist's reason
- state is refetched after successful mutations

Revproxy tests or deployment checks should cover:

- `/authz/access/user` reaches Arborist `/access/user`
- authenticated proxy headers are forwarded
- CSRF behavior matches ownership routes

## Developer Rules

- Do not hardcode product role names in Arborist access macros.
- Do not expose policy ids as required mutation inputs for normal UI access
  changes.
- Do not make the frontend classify Arborist grant provenance.
- Do not silently return success when an effective grant was not removed.
- Do not remove inherited, group-derived, protected, owner, or broad grants
  from the direct access macro.
- Do not move this logic into Requestor.
- Keep missing-resource creation in ownership descendant APIs.
- Keep owner management in ownership owner APIs.
- Keep direct user access management in access macros.
