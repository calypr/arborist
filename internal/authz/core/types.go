package core

type Action struct {
	Service string `json:"service"`
	Method  string `json:"method"`
}

type Constraints = map[string]string

const (
	CreateDescendantMethod = "create-descendant"

	AnonymousGroup = "anonymous"
	LoggedInGroup  = "logged-in"

	SubjectTypeUser   = "user"
	SubjectTypeGroup  = "group"
	SubjectTypeClient = "client"
)

type TokenInfo struct {
	Username string
	ClientID string
	Policies []string
}
