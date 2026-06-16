package engine

import (
	"encoding/json"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
)

type AuthRequestJSON struct {
	User     AuthRequestJSON_User      `json:"user"`
	Request  *AuthRequestJSON_Request  `json:"request"`
	Requests []AuthRequestJSON_Request `json:"requests"`
}

type AuthRequestJSON_User struct {
	Token  string `json:"token"`
	UserId string `json:"user_id"`
	// The Policies field is optional, and if the request provides a token
	// this gets filled in using the Token field.
	// Could use UserId if its provided instead of Token
	Policies []string `json:"policies,omitempty"`
	Scopes   []string `json:"scope,omitempty"`
}

func (requestJSON *AuthRequestJSON_User) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}

	optionalFields := map[string]struct{}{
		"policies": {},
		"scope":    {},
	}

	// either user_id is required or token is required
	// if one is provided the other should be optional
	if _, exists := fields["user_id"]; !exists {
		optionalFields["user_id"] = struct{}{}
	} else if _, exists := fields["token"]; !exists {
		optionalFields["token"] = struct{}{}
	}

	err = coreauthz.ValidateJSON("auth request", requestJSON, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the AuthRequestJSON to.
	type loader AuthRequestJSON_User
	err = json.Unmarshal(data, (*loader)(requestJSON))
	if err != nil {
		return err
	}

	return nil
}

type AuthRequestJSON_Request struct {
	Resource    string                `json:"resource"`
	Action      coreauthz.Action      `json:"action"`
	Constraints coreauthz.Constraints `json:"constraints,omitempty"`
}

// UnmarshalJSON defines the deserialization from JSON into an AuthRequestJSON
// struct, which includes validating that required fields are present.
// (Required fields are anything not in the `optionalFields` variable.)
func (requestJSON *AuthRequestJSON_Request) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}

	optionalFieldsPath := map[string]struct{}{
		"constraints": {},
	}
	err = coreauthz.ValidateJSON("auth request", requestJSON, fields, optionalFieldsPath)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the AuthRequestJSON to.
	type loader AuthRequestJSON_Request
	err = json.Unmarshal(data, (*loader)(requestJSON))
	if err != nil {
		return err
	}

	return nil
}

type AuthRequest struct {
	Username string
	ClientID string
	Policies []string
	Resource string
	Service  string
	Method   string
	stmts    *coreauthz.CachedStmts
}

func (request *AuthRequest) WithStmts(stmts *coreauthz.CachedStmts) *AuthRequest {
	request.stmts = stmts
	return request
}

type AuthResponse struct {
	Auth bool `json:"auth"`
}

// Authorize a request where the end user is anonymous, so there is no token
// involved, and access is granted only through the built-in anonymous group.
