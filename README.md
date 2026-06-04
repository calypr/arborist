# Arborist

Arborist is an attribute-based access control (ABAC) policy engine, designed for use with
the [Gen3 stack](https://gen3.org/). Arborist tracks resources requiring access
control, along with actions which users may perform to operate on these
resources, and roles, which aggregate permissions to perform one or more
actions. Finally, policies tie together a set of resources with a set of roles;
when granted to a user, a policy grants authorization to act as one of the roles
over one of the resources. Resources are arranged hierarchically like a
filesystem, and access to one resource implies access to its subresources.

For example, a simple policy might grant a role `metadata-submitter` on the
resource `/projects/project-abc`. Now users which are granted this policy can
perform the actions that being a `metadata-submitter` entails, for all resources
under `project-abc`.

In the Gen3 stack, arborist is integrated closely with fence. Fence acts as the
central identity provider, issuing user tokens (in the form of JWTs) containing
the list of policies in the arborist model which are granted to that user. Other
microservices needing to check user authorization to operate on a resource can
statelessly verify the user's authorization, making a request to arborist with
the user's JWT and receiving a response for the authorization decision.

The key documentation is below. Additional documentation can be found in the [/docs](/docs) directory.

## API documentation

[OpenAPI documentation available here.](http://petstore.swagger.io/?url=https://raw.githubusercontent.com/calypr/arborist/master/docs/openapi.yaml)

The YAML file containing the OpenAPI documentation can be found in the `docs` folder.

## Dynamic Resource Ownership

This branch also adds the Arborist-side permission model for the
`feature/github-permissions` product flow. See
[docs/github_permissions.md](docs/github_permissions.md) for a branch-level
overview of what changed and how the ownership and access APIs fit together.

This fork adds GitHub-style descendant ownership for dynamic Calypr project
creation. See [docs/descendant_ownership.md](docs/descendant_ownership.md) for
the architecture, API contracts, invariants, and operational notes.

This fork also adds Arborist access mutation macros for direct owner/admin
project access management. See
[docs/access_mutation_macros.md](docs/access_mutation_macros.md) for the
technical rationale behind `/access/user`, legacy RBAC compatibility, and why
the macro lives in Arborist instead of Requestor.

## Setup

### Quickstart

You will need these:

- [Go](https://golang.org/dl/)
- [PostgreSQL](https://www.postgresql.org/download/)
- a Postgres superuser--Arborist uses the Postgres `ltree` extension module, and the `CREATE EXTENSION` command [must be run by a database superuser](https://www.postgresql.org/docs/9.6/contrib.html).

```bash
# clone it
git clone https://github.com/calypr/arborist.git
cd arborist

# build the code
make

# set up database; use whatever values for database name etc. you like,
# but PGUSER must be a postgres superuser
export \
    PGDATABASE=arborist_test \
    PGUSER=username \
    PGPASSWORD=password \
    PGHOST=localhost \
    PGPORT=5432 \
    PGSSLMODE=disable
# export any other PG variables as necessary. `PGSSLMODE=disable` is required, though.
# create the database for the first time
createdb
# bring the database schema up to the latest version
./migrations/latest

# example command to run the server (see also `--help`):
./bin/arborist --port 8080 --jwks https://dev.planx-pla.net/user/.well-known/jwks
```

### Quickstart with Helm

You can now deploy individual services via Helm! 
Please refer to the Helm quickstart guide HERE (https://github.com/calypr/arborist/blob/master/docs/quickstart_helm.md)

### Building With Docker

There is also the `Dockerfile` in the root directory which is used to build a
Docker image for the server. In short, run this command from the root directory
to build an image:
```bash
docker build -t arborist .
```
Run the docker image:
```bash
docker run -p 8080:8080 arborist --port 8080 # plus other arguments
```
(This command exposes arborist on port 8080 in the docker image, and maps port
8080 from the docker image onto 8080 on the host machine.) See also Docker
documentation for more details on how to use Docker.

### Building From GitHub

Clone/Build/Install all-in-one command:

```bash
go install github.com/calypr/arborist/cmd/arborist@latest
```

If you already have a local checkout, you can also run `go build .` from the
repository root to build the server binary directly.

### Building From Source

If you have already checked out the repository locally, you can build the
executable from there directly, which will include any local changes during
development.

Running `make` will build the code:
```bash
make
```

The project is module-aware, so `go build .` and `go test ./...` work from a
normal checkout without needing a GOPATH-specific directory layout.

## Terminology and Definitions

We will start from the lowest-level definitions, and work upwards.

- *Action:* a method (identified by a string) on a service (also identified by
  string) and generally correspond directly to an endpoint or simple operation
  done through the given service. An example might be something like this:
```
{
    "service": "fence",
    "method": "presigned-url-download",
}
```
- *Permission:* a combination of an action, and some optional constraints
  (key-value pairs which restrict the context of the action).
- *Role:* collections of permissions. Roles are uniquely identified by an ID
  field.
- *Resource:* anything that should be access-controlled, organized like
  directories of a filesystem. Resources are uniquely identifiable by their full
  path. Resources can have "child" resources (subdirectories, or
  sub-subdirectories etc., in the filesystem model), where access to one
  resource implies access to all the resources below it. A resource might be,
  for example, an entire project in a data commons, like
  `/projects/project-abc`.
- *Policy:* combines a set of roles and resources together, with the meaning
  that the policy allows access to use any of its roles on any of its resources.
  Policies are granted to users and groups to give them access.
- *Group:* a set of users. Groups can be granted their own policies; this gives
  access to that policy for all users in the group.

## Configuring Access

Ultimately, the flowchart for granting access to users goes something like the
following:

1. Create roles, resources, and policies to define access.
2. One or more of the following:
  - Using groups:
    1. Grant a policy to a group (`/group/{group}/policy` endpoint).
    2. Add users to the group (`/group/{group}/user` endpoint).
    3. Users in the group now have access.
  - For generic permissions which should be granted to all users (including
    anonymous users, or only those who are logged in, i.e. have a JWT):
    1. Grant a policy to the built-in `anonymous` and/or `logged-in` groups.
       (`/group/anonymous/policy` and `/group/logged-in/policy` endpoints)
    2. Now users even without a JWT have access using the policies granted to
       the `anonymous` group, and all users with just a JWT have access to the
       policies for the `logged-in` group. (All users are implicitly considered
       part of the `logged-in` group.)
  - Specifying permissions for individual users directly:
    1. Grant an individual user a policy (`/user/{username}/policy` endpoint).
    2. Now that user has access.

## Development

See [development documentation](./docs/DEVELOP.md).

## DB diagram

See [DB diagram](./docs/db_diagram.md).
