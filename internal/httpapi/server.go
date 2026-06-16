package httpapi

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/calypr/arborist/internal/authz/epoch"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type JWTDecoder interface {
	Decode(string) (*map[string]interface{}, error)
}

type Server struct {
	db     *sqlx.DB
	jwtApp JWTDecoder
	logger *coreauthz.LogHandler
	stmts  *coreauthz.CachedStmts
}

func NewServer() *Server {
	return &Server{}
}

func (server *Server) WithLogger(logger *log.Logger) *Server {
	server.logger = coreauthz.NewLogHandler(logger)
	return server
}

func (server *Server) WithJWTApp(jwtApp JWTDecoder) *Server {
	server.jwtApp = jwtApp
	return server
}

func (server *Server) WithDB(db *sqlx.DB) *Server {
	server.db = db
	server.stmts = coreauthz.NewCachedStmts(db)
	return server
}

func (server *Server) Init() (*Server, error) {
	if server.db == nil {
		return nil, errors.New("arborist server initialized without database")
	}
	if server.jwtApp == nil {
		return nil, errors.New("arborist server initialized without JWT app")
	}
	if server.logger == nil {
		return nil, errors.New("arborist server initialized without logger")
	}
	epoch.ConfigureAuthzEpochRedis(server.logger)

	return server, nil
}

// For some reason this is not allowed:
//
//	`{resourcePath:/.+}`
//
// so we put the slash at the front here and fix it in parseResourcePath.
const resourcePath string = `/{resourcePath:.+}`

func parseResourcePath(r *http.Request) string {
	path, exists := mux.Vars(r)["resourcePath"]
	if !exists {
		return ""
	}
	// We have to add a slash at the front here; see resourcePath constant.
	return strings.Join([]string{"/", path}, "")
}

func getAuthZProvider(r *http.Request) sql.NullString {
	rv := r.Header.Get("X-AuthZ-Provider")
	if len(rv) == 0 {
		return sql.NullString{}
	} else {
		return sql.NullString{String: rv, Valid: true}
	}
}

func (server *Server) MakeRouter(out io.Writer) http.Handler {
	router := mux.NewRouter().StrictSlash(true)

	//router.Handle("/", server.handleRoot).Methods("GET")

	router.HandleFunc("/health", server.handleHealth).Methods("GET")

	router.Handle("/auth/mapping", http.HandlerFunc(server.handleAuthMappingGET)).Methods("GET")
	router.Handle("/auth/mapping", http.HandlerFunc(server.handleAuthMappingPOST)).Methods("POST")
	router.Handle("/auth/proxy", http.HandlerFunc(server.handleAuthProxy)).Methods("GET")
	router.Handle("/auth/request", http.HandlerFunc(server.parseJSON(server.handleAuthRequest))).Methods("POST")
	router.Handle("/auth/resources", http.HandlerFunc(server.handleListAuthResourcesGET)).Methods("GET")
	router.Handle("/auth/resources", http.HandlerFunc(server.parseJSON(server.handleListAuthResourcesPOST))).Methods("POST")

	router.Handle("/policy", http.HandlerFunc(server.handlePolicyList)).Methods("GET")
	router.Handle("/policy", http.HandlerFunc(server.parseJSON(server.handlePolicyCreate))).Methods("POST")
	// delete this (PUT /policy) route after 3.0.0
	router.Handle("/policy", http.HandlerFunc(server.parseJSON(server.handlePolicyOverwrite))).Methods("PUT")
	router.Handle("/policy/{policyID}", http.HandlerFunc(server.parseJSON(server.handlePolicyOverwrite))).Methods("PUT")
	router.Handle("/policy/{policyID}", http.HandlerFunc(server.handlePolicyRead)).Methods("GET")
	router.Handle("/policy/{policyID}", http.HandlerFunc(server.handlePolicyDelete)).Methods("DELETE")
	router.Handle("/bulk/policy", http.HandlerFunc(server.parseJSON(server.handleBulkPoliciesOverwrite))).Methods("PUT")
	router.Handle("/ownership/descendant", http.HandlerFunc(server.parseJSON(server.handleOwnershipCreateDescendant))).Methods("POST")
	router.Handle("/ownership/resource", http.HandlerFunc(server.handleOwnershipResourceRead)).Methods("GET")
	router.Handle("/ownership/resource", http.HandlerFunc(server.handleOwnershipResourceDelete)).Methods("DELETE")
	router.Handle("/ownership/owner", http.HandlerFunc(server.parseJSON(server.handleOwnershipAddOwner))).Methods("POST")
	router.Handle("/ownership/owner", http.HandlerFunc(server.parseJSON(server.handleOwnershipRemoveOwner))).Methods("DELETE")
	router.Handle("/access/user", http.HandlerFunc(server.parseJSON(server.handleAccessGrantUser))).Methods("POST")
	router.Handle("/access/user", http.HandlerFunc(server.parseJSON(server.handleAccessRevokeUser))).Methods("DELETE")

	router.Handle("/resource", http.HandlerFunc(server.handleResourceList)).Methods("GET")
	router.Handle("/resource", http.HandlerFunc(server.parseJSON(server.handleResourceCreate))).Methods("POST", "PUT")
	router.Handle("/resource/tag/{tag}", http.HandlerFunc(server.handleResourceReadByTag)).Methods("GET")
	router.Handle("/resource"+resourcePath, http.HandlerFunc(server.handleResourceRead)).Methods("GET")
	router.Handle("/resource"+resourcePath, http.HandlerFunc(server.parseJSON(server.handleResourceCreate))).Methods("POST", "PUT")
	router.Handle("/resource"+resourcePath, http.HandlerFunc(server.handleResourceDelete)).Methods("DELETE")

	router.Handle("/role", http.HandlerFunc(server.handleRoleList)).Methods("GET")
	router.Handle("/role", http.HandlerFunc(server.parseJSON(server.handleRoleCreate))).Methods("POST")
	router.Handle("/role/{roleID}", http.HandlerFunc(server.handleRoleRead)).Methods("GET")
	router.Handle("/role/{roleID}", http.HandlerFunc(server.parseJSON(server.handleRoleOverwrite))).Methods("PUT")
	router.Handle("/role/{roleID}", http.HandlerFunc(server.handleRoleDelete)).Methods("DELETE")

	router.Handle("/user", http.HandlerFunc(server.handleUserList)).Methods("GET")
	router.Handle("/user", http.HandlerFunc(server.parseJSON(server.handleUserCreate))).Methods("POST")
	router.Handle("/user/{username}", http.HandlerFunc(server.handleUserRead)).Methods("GET")
	router.Handle("/user/{username}", http.HandlerFunc(server.parseJSON(server.handleUserUpdate))).Methods("PATCH")
	router.Handle("/user/{username}/policy", http.HandlerFunc(server.parseJSON(server.handleUserGrantPolicy))).Methods("POST")
	router.Handle("/user/{username}/bulk/policy", http.HandlerFunc(server.parseJSON(server.handleBulkUserGrantPolicy))).Methods("POST")
	router.Handle("/user/{username}/policy", http.HandlerFunc(server.handleUserRevokeAll)).Methods("DELETE")
	router.Handle("/user/{username}/policy/{policyName}", http.HandlerFunc(server.handleUserRevokePolicy)).Methods("DELETE")
	router.Handle("/user/{username}/resources", http.HandlerFunc(server.handleUserListResources)).Methods("GET")
	// Define this one last because `{username:.*}` matches any character, including slashes.
	// Other `/user/{username}/xyz` routes must be defined first to be reachable.
	// Slashes in usernames are not supported by all endpoints, but they should be supported here
	// so the users can at least be deleted.
	router.Handle("/user/{username:.*}", http.HandlerFunc(server.handleUserDelete)).Methods("DELETE")

	router.Handle("/client", http.HandlerFunc(server.handleClientList)).Methods("GET")
	router.Handle("/client", http.HandlerFunc(server.parseJSON(server.handleClientCreate))).Methods("POST")
	router.Handle("/client/{clientID}", http.HandlerFunc(server.handleClientRead)).Methods("GET")
	router.Handle("/client/{clientID}", http.HandlerFunc(server.handleClientDelete)).Methods("DELETE")
	router.Handle("/client/{clientID}/policy", http.HandlerFunc(server.parseJSON(server.handleClientGrantPolicy))).Methods("POST")
	router.Handle("/client/{clientID}/policy", http.HandlerFunc(server.handleClientRevokeAll)).Methods("DELETE")
	router.Handle("/client/{clientID}/policy/{policyName}", http.HandlerFunc(server.handleClientRevokePolicy)).Methods("DELETE")

	router.Handle("/group", http.HandlerFunc(server.handleGroupList)).Methods("GET")
	router.Handle("/group", http.HandlerFunc(server.parseJSON(server.handleGroupCreate))).Methods("POST", "PUT")
	router.Handle("/group/{groupName}", http.HandlerFunc(server.handleGroupRead)).Methods("GET")
	router.Handle("/group/{groupName}", http.HandlerFunc(server.handleGroupDelete)).Methods("DELETE")
	router.Handle("/group/{groupName}/user", http.HandlerFunc(server.parseJSON(server.handleGroupAddUser))).Methods("POST")
	router.Handle("/group/{groupName}/user/{username}", http.HandlerFunc(server.handleGroupRemoveUser)).Methods("DELETE")
	router.Handle("/group/{groupName}/policy", http.HandlerFunc(server.parseJSON(server.handleGroupGrantPolicy))).Methods("POST")
	router.Handle("/group/{groupName}/policy/{policyName}", http.HandlerFunc(server.handleGroupRevokePolicy)).Methods("DELETE")

	router.NotFoundHandler = http.HandlerFunc(handleNotFound)

	// remove trailing slashes sent in URLs
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimSuffix(r.URL.Path, "/")
		router.ServeHTTP(w, r)
	})

	return handlers.CombinedLoggingHandler(out, handler)
}

// parseJSON abstracts JSON parsing for handler functions that should
// receive a valid JSON input in the request body. It takes a modified
// handler function as input, which should include the body in `[]byte`
// form as an additional argument, and returns a function with the usual
// handler signature.
func (server *Server) parseJSON(baseHandler func(http.ResponseWriter, *http.Request, []byte)) func(http.ResponseWriter, *http.Request) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		body, err := server.parseJsonBody(w, r)
		if err != nil {
			server.writeError(w, r, err)
			return
		}
		if body == nil {
			err := coreauthz.NewErrorResponse("expected JSON body in the request", 400, nil)
			server.writeError(w, r, err)
			return
		}
		baseHandler(w, r, body)
	}
	return handler
}

func (server *Server) parseJsonBody(w http.ResponseWriter, r *http.Request) ([]byte, *coreauthz.ErrorResponse) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		msg := fmt.Sprintf("could not parse valid JSON from request: %s", err.Error())
		err := coreauthz.NewErrorResponse(msg, 400, nil)
		return nil, err
	}
	return body, nil
}

func (server *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	err := server.db.Ping()
	if err != nil {
		server.logger.Error("database ping failed; returning unhealthy")
		response := coreauthz.NewErrorResponse("database unavailable", 500, nil)
		server.writeError(w, r, response)
		return
	}
	_ = jsonResponseFrom("Healthy", http.StatusOK).write(w, r)
}

func handleNotFound(w http.ResponseWriter, r *http.Request) {
	response := struct {
		Error struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		} `json:"error"`
	}{
		Error: struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		}{
			Message: "not found",
			Code:    404,
		},
	}
	_ = jsonResponseFrom(response, 404).write(w, r)
}
