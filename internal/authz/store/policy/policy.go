package policy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/calypr/arborist/internal/authz/protection"
	"github.com/calypr/arborist/internal/authz/store/resource"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Policy struct {
	Name          string   `json:"id"`
	Description   string   `json:"description"`
	ResourcePaths []string `json:"resource_paths"`
	RoleIDs       []string `json:"role_ids"`
}

type PolicyOut = policyOut

type policyOut struct {
	Name          string   `json:"id"`
	Description   string   `json:"description"`
	ResourcePaths []string `json:"resource_paths"`
	RoleIDs       []string `json:"role_ids"`
	Generated     bool     `json:"generated,omitempty"`
	Protected     bool     `json:"protected,omitempty"`
	GeneratedKind string   `json:"generated_kind,omitempty"`
	TemplateName  string   `json:"template_name,omitempty"`
}

// expanded policies need their own struct so that unused RoleIDs/Roles
// fields can be excluded from the JSON response
type ExpandedPolicy struct {
	Name          string   `json:"id"`
	Description   string   `json:"description"`
	ResourcePaths []string `json:"resource_paths"`
	Roles         []Role   `json:"roles"`
}

// UnmarshalJSON defines the way that a `Policy` gets read when unmarshalling:
//
//	json.Unmarshal(bytes, &policy)
//
// We implement this method to add some additional processing and error
// checking, for example to reject inputs which are missing required fields.
func (policy *Policy) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}

	// id is optional here because PUT doesn't require it to be in the json;
	// handlePolicyOverwrite will populate id later, from the URL.
	// id is still validated later, in policy `validate` function.
	optionalFields := map[string]struct{}{
		"id":          {},
		"description": {},
	}
	err = coreauthz.ValidateJSON("policy", policy, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the PolicyJSON to.
	type loader Policy
	err = json.Unmarshal(data, (*loader)(policy))
	if err != nil {
		return err
	}

	return nil
}

// PolicyFromQuery defines the correct fields for loading policies from the
// database. Use this struct when querying from the `policy` table.
type PolicyFromQuery struct {
	ID            int64          `db:"id" json:"-"`
	Name          string         `db:"name" json:"id"`
	Description   *string        `db:"description" json:"description,omitempty"`
	ResourcePaths pq.StringArray `db:"resource_paths" json:"resource_paths"`
	RoleIDs       pq.StringArray `db:"role_ids" json:"role_ids"`
	Generated     sql.NullBool   `db:"generated" json:"generated,omitempty"`
	Protected     sql.NullBool   `db:"protected" json:"protected,omitempty"`
	GeneratedKind sql.NullString `db:"generated_kind" json:"generated_kind,omitempty"`
	TemplateName  sql.NullString `db:"template_name" json:"template_name,omitempty"`
}

func (policyFromQuery *PolicyFromQuery) standardize() Policy {
	paths := make([]string, len(policyFromQuery.ResourcePaths))
	for i, queryPath := range policyFromQuery.ResourcePaths {
		paths[i] = coreauthz.FormatDbPath(queryPath)
	}
	policy := Policy{
		Name:          policyFromQuery.Name,
		ResourcePaths: paths,
		RoleIDs:       policyFromQuery.RoleIDs,
	}
	if policyFromQuery.Description != nil {
		policy.Description = *policyFromQuery.Description
	}
	return policy
}

func (policyFromQuery *PolicyFromQuery) Standardize() Policy {
	return policyFromQuery.standardize()
}

func (policyFromQuery *PolicyFromQuery) standardizeOut() policyOut {
	policy := policyFromQuery.standardize()
	out := policyOut{
		Name:          policy.Name,
		Description:   policy.Description,
		ResourcePaths: policy.ResourcePaths,
		RoleIDs:       policy.RoleIDs,
	}
	if policyFromQuery.Generated.Valid {
		out.Generated = policyFromQuery.Generated.Bool
	}
	if policyFromQuery.Protected.Valid {
		out.Protected = policyFromQuery.Protected.Bool
	}
	if policyFromQuery.GeneratedKind.Valid {
		out.GeneratedKind = policyFromQuery.GeneratedKind.String
	}
	if policyFromQuery.TemplateName.Valid {
		out.TemplateName = policyFromQuery.TemplateName.String
	}
	return out
}

func (policyFromQuery *PolicyFromQuery) StandardizeOut() policyOut {
	return policyFromQuery.standardizeOut()
}

func policyWithName(db *sqlx.DB, name string) (*PolicyFromQuery, error) {
	stmt := `
		SELECT
			policy.id,
			policy.name,
			policy.description,
			(generated_policy_metadata.policy_id IS NOT NULL) AS generated,
			generated_policy_metadata.protected AS protected,
			generated_policy_metadata.kind AS generated_kind,
			generated_policy_metadata.template_name AS template_name,
			array_remove(array_agg(DISTINCT resource.path), NULL) AS resource_paths,
			array_remove(array_agg(DISTINCT role.name), NULL) AS role_ids
		FROM policy
		LEFT JOIN generated_policy_metadata ON policy.id = generated_policy_metadata.policy_id
		LEFT JOIN policy_resource ON policy.id = policy_resource.policy_id
		LEFT JOIN resource ON resource.id = policy_resource.resource_id
		LEFT JOIN policy_role on policy.id = policy_role.policy_id
		LEFT JOIN role on role.id = policy_role.role_id
		WHERE policy.name = $1
		GROUP BY
			policy.id,
			generated_policy_metadata.policy_id,
			generated_policy_metadata.protected,
			generated_policy_metadata.kind,
			generated_policy_metadata.template_name
		LIMIT 1
	`
	policies := []PolicyFromQuery{}
	err := db.Select(&policies, stmt, name)
	if len(policies) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	policy := policies[0]
	return &policy, nil
}

func listPoliciesFromDb(db *sqlx.DB) ([]PolicyFromQuery, error) {
	stmt := `
		SELECT
			policy.id,
			policy.name,
			policy.description,
			(generated_policy_metadata.policy_id IS NOT NULL) AS generated,
			generated_policy_metadata.protected AS protected,
			generated_policy_metadata.kind AS generated_kind,
			generated_policy_metadata.template_name AS template_name,
			array_remove(array_agg(DISTINCT resource.path), NULL) AS resource_paths,
			array_remove(array_agg(DISTINCT role.name), NULL) AS role_ids
		FROM policy
		LEFT JOIN generated_policy_metadata ON policy.id = generated_policy_metadata.policy_id
		LEFT JOIN policy_resource ON policy.id = policy_resource.policy_id
		LEFT JOIN resource ON resource.id = policy_resource.resource_id
		LEFT JOIN policy_role on policy.id = policy_role.policy_id
		LEFT JOIN role on role.id = policy_role.role_id
		GROUP BY
			policy.id,
			generated_policy_metadata.policy_id,
			generated_policy_metadata.protected,
			generated_policy_metadata.kind,
			generated_policy_metadata.template_name
	`
	var policies []PolicyFromQuery
	err := db.Select(&policies, stmt)
	if err != nil {
		return nil, err
	}
	return policies, nil
}

func ListPoliciesFromDb(db *sqlx.DB) ([]PolicyFromQuery, error) {
	return listPoliciesFromDb(db)
}

func PolicyWithName(db *sqlx.DB, name string) (*PolicyFromQuery, error) {
	return policyWithName(db, name)
}

// resources looks up all the resources with paths in this policy. An error, if
// returned, resulted from the database operation.
func (policy *Policy) resources(tx *sqlx.Tx) ([]resource.ResourceFromQuery, error) {
	resources := []resource.ResourceFromQuery{}
	queryPaths := make([]string, len(policy.ResourcePaths))
	for i, path := range policy.ResourcePaths {
		queryPaths[i] = coreauthz.FormatPathForDb(path)
	}
	resourcesStmt := coreauthz.SelectInStmt("resource", "ltree2text(path)", queryPaths)
	err := tx.Select(&resources, resourcesStmt)
	if err != nil {
		return nil, err
	}
	return resources, nil
}

// roles looks up the roles which this policy references. An error, if
// returned, resulted from the database operation.
func (policy *Policy) roles(tx *sqlx.Tx) ([]RoleFromQuery, error) {
	roles := []RoleFromQuery{}
	rolesStmt := coreauthz.SelectInStmt("role", "name", policy.RoleIDs)
	err := tx.Select(&roles, rolesStmt)
	if err != nil {
		return nil, err
	}
	return roles, nil
}

// validate does any basic validation on the policy which is possible without
// looking at the database. This includes that the policy must contain at least
// one resource and at least one role.
func (policy *Policy) validate() *coreauthz.ErrorResponse {
	if len(policy.Name) == 0 {
		return coreauthz.NewErrorResponse("policy ID cannot be absent or empty", 400, nil)
	}
	// Resources and roles must be non-empty
	if len(policy.ResourcePaths) == 0 {
		return coreauthz.NewErrorResponse("no resource paths specified", 400, nil)
	}
	if len(policy.RoleIDs) == 0 {
		return coreauthz.NewErrorResponse("no role IDs specified", 400, nil)
	}
	return nil
}

// addResourcesAndRoles takes a policy and links it in the database
// to each of its resources and roles.
func (policy *Policy) addResourcesAndRoles(tx *sqlx.Tx, policyID int) *coreauthz.ErrorResponse {

	// `resources` is a list of looked-up resources which appear in the input policy
	resources, err := policy.resources(tx)
	if err != nil {
		msg := fmt.Sprintf("database call for resources failed: %s", err.Error())
		return coreauthz.NewErrorResponse(msg, 500, &err)
	}
	// make sure all resources for new policy exist in DB
	resourceSet := make(map[string]struct{})
	for _, resource := range resources {
		path := coreauthz.FormatDbPath(resource.Path)
		resourceSet[path] = struct{}{}
	}
	missingResources := []string{}
	for _, path := range policy.ResourcePaths {
		if _, exists := resourceSet[path]; !exists {
			missingResources = append(missingResources, path)
		}
	}
	if len(missingResources) > 0 {
		missingString := strings.Join(missingResources, ", ")
		msg := fmt.Sprintf("failed to create policy: resources do not exist: %s", missingString)
		return coreauthz.NewErrorResponse(msg, 400, nil)
	}
	// try to insert relationships from this policy to all resources
	stmt := coreauthz.MultiInsertStmt("policy_resource(policy_id, resource_id)", len(resources))
	policyResourceRows := []interface{}{}
	for _, resource := range resources {
		policyResourceRows = append(policyResourceRows, policyID)
		policyResourceRows = append(policyResourceRows, resource.ID)
	}
	_, err = tx.Exec(stmt, policyResourceRows...)
	if err != nil {
		msg := fmt.Sprintf("failed to insert policy while linking resources: %s", err.Error())
		return coreauthz.NewErrorResponse(msg, 500, &err)
	}

	roles, err := policy.roles(tx)
	if err != nil {
		msg := fmt.Sprintf("database call for roles failed: %s", err.Error())
		return coreauthz.NewErrorResponse(msg, 500, &err)
	}
	// make sure all resources for new policy exist in DB
	roleSet := make(map[string]struct{})
	for _, role := range roles {
		roleSet[role.Name] = struct{}{}
	}
	missingRoles := []string{}
	for _, role := range policy.RoleIDs {
		if _, exists := roleSet[role]; !exists {
			missingRoles = append(missingRoles, role)
		}
	}
	if len(missingRoles) > 0 {
		missingString := strings.Join(missingRoles, ", ")
		msg := fmt.Sprintf("failed to create policy: roles do not exist: %s", missingString)
		return coreauthz.NewErrorResponse(msg, 400, nil)
	}
	// try to insert relationships from this policy to all roles
	stmt = coreauthz.MultiInsertStmt("policy_role(policy_id, role_id)", len(roles))
	policyRoleRows := []interface{}{}
	for _, role := range roles {
		policyRoleRows = append(policyRoleRows, policyID)
		policyRoleRows = append(policyRoleRows, role.ID)
	}
	_, err = tx.Exec(stmt, policyRoleRows...)
	if err != nil {
		msg := fmt.Sprintf("failed to insert policy while linking roles: %s", err.Error())
		return coreauthz.NewErrorResponse(msg, 500, &err)
	}

	return nil
}

// createInDb writes out the policy to the database.
func (policy *Policy) createInDb(tx *sqlx.Tx) *coreauthz.ErrorResponse {
	errResponse := policy.validate()
	if errResponse != nil {
		return errResponse
	}

	var policyID int
	// TODO: make sure description works as expected
	stmt := "INSERT INTO policy(name, description) VALUES ($1, $2) RETURNING id"
	row := tx.QueryRowx(stmt, policy.Name, policy.Description)
	err := row.Scan(&policyID)
	if err != nil {
		// should add more checking here to guarantee the correct error
		// this should only fail because the policy was not unique. return error
		// accordingly
		msg := fmt.Sprintf("failed to insert policy: policy with this ID already exists: %s", policy.Name)
		return coreauthz.NewErrorResponse(msg, 409, &err)
	}

	errResponse = policy.addResourcesAndRoles(tx, policyID)
	if errResponse != nil {
		return errResponse
	}

	return nil
}

func (policy *Policy) CreateInDb(tx *sqlx.Tx) *coreauthz.ErrorResponse {
	return policy.createInDb(tx)
}

func (policy *Policy) deleteInDb(tx *sqlx.Tx) *coreauthz.ErrorResponse {
	protected, errResponse := protection.GeneratedPolicyIsProtected(tx, policy.Name)
	if errResponse != nil {
		return errResponse
	}
	if protected {
		msg := fmt.Sprintf("cannot delete protected generated policy: %s", policy.Name)
		return coreauthz.NewErrorResponse(msg, 403, nil)
	}
	stmt := "DELETE FROM policy WHERE name = $1"
	_, err := tx.Exec(stmt, policy.Name)
	if err != nil {
		// TODO: verify correct error
		// doesn't exist, this is fine
		return nil
	}
	return nil
}

func (policy *Policy) DeleteInDb(tx *sqlx.Tx) *coreauthz.ErrorResponse {
	return policy.deleteInDb(tx)
}

func (policy *Policy) updateInDb(tx *sqlx.Tx) *coreauthz.ErrorResponse {
	// We do not allow updates to policy name (or id).
	protected, protectedErr := protection.GeneratedPolicyIsProtected(tx, policy.Name)
	if protectedErr != nil {
		return protectedErr
	}
	if protected {
		msg := fmt.Sprintf("cannot overwrite protected generated policy: %s", policy.Name)
		return coreauthz.NewErrorResponse(msg, 403, nil)
	}

	errResponse := policy.validate()
	if errResponse != nil {
		return errResponse
	}

	var policyID int
	stmt := "UPDATE policy SET description = $1 WHERE name = $2 RETURNING id"
	row := tx.QueryRowx(stmt, policy.Description, policy.Name)
	err := row.Scan(&policyID)
	switch {
	case err == sql.ErrNoRows:
		msg := fmt.Sprintf("failed to update policy: no policy found with id: %s", policy.Name)
		return coreauthz.NewErrorResponse(msg, 404, &err)
	case err != nil:
		msg := fmt.Sprintf("failed to update policy: update description failed: %s", err.Error())
		return coreauthz.NewErrorResponse(msg, 500, &err)
	}

	// First delete resources and roles that were previously attached to policy
	stmt = "DELETE FROM policy_resource WHERE policy_id = $1"
	_, err = tx.Exec(stmt, policyID)
	if err != nil {
		msg := fmt.Sprintf("database deletion from policy_resource failed: %s", err.Error())
		return coreauthz.NewErrorResponse(msg, 500, &err)
	}
	stmt = "DELETE FROM policy_role WHERE policy_id = $1"
	_, err = tx.Exec(stmt, policyID)
	if err != nil {
		msg := fmt.Sprintf("database deletion from policy_role failed: %s", err.Error())
		return coreauthz.NewErrorResponse(msg, 500, &err)
	}

	// Now add the new resources and roles
	errResponse = policy.addResourcesAndRoles(tx, policyID)
	if errResponse != nil {
		return errResponse
	}

	return nil
}

func (policy *Policy) UpdateInDb(tx *sqlx.Tx) *coreauthz.ErrorResponse {
	return policy.updateInDb(tx)
}
