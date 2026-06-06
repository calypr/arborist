package arborist

import (
	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/calypr/arborist/internal/authz/engine"
	"github.com/calypr/arborist/internal/authz/store/policy"
	principal "github.com/calypr/arborist/internal/authz/store/principal"
	"github.com/calypr/arborist/internal/authz/store/resource"
)

type Action = coreauthz.Action
type Permission = policy.Permission
type Constraints = coreauthz.Constraints

type AuthRequestJSON = engine.AuthRequestJSON
type AuthRequestJSON_User = engine.AuthRequestJSON_User
type AuthRequestJSON_Request = engine.AuthRequestJSON_Request

type AuthRequest = engine.AuthRequest
type AuthResponse = engine.AuthResponse
type AuthMapping = engine.AuthMapping

type ResourceIn = resource.ResourceIn
type ResourceOut = resource.ResourceOut
type ResourceFromQuery = resource.ResourceFromQuery

type Policy = policy.Policy
type PolicyOut = policy.PolicyOut
type PolicyFromQuery = policy.PolicyFromQuery
type ExpandedPolicy = policy.ExpandedPolicy

type Role = policy.Role
type RoleFromQuery = policy.RoleFromQuery

type User = principal.User
type UserWithScalars = principal.UserWithScalars
type UserFromQuery = principal.UserFromQuery
type PolicyBinding = principal.PolicyBinding
type UserPolicyInfoFromQuery = principal.UserPolicyInfoFromQuery

type Client = principal.Client
type ClientFromQuery = principal.ClientFromQuery

type Group = principal.Group
type GroupFromQuery = principal.GroupFromQuery

type HTTPError = coreauthz.HTTPError
type ErrorResponse = coreauthz.ErrorResponse
