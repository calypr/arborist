package httpapi

import (
	"encoding/json"
	"net/http"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
)

type jsonResponse struct {
	content interface{}
	code    int
}

func jsonResponseFrom(content interface{}, code int) *jsonResponse {
	return &jsonResponse{
		content: content,
		code:    code,
	}
}

func wantPrettyJSON(r *http.Request) bool {
	prettyJSON := false
	if r.Method == "GET" {
		prettyJSON = prettyJSON || r.URL.Query().Get("pretty") == "true"
		prettyJSON = prettyJSON || r.URL.Query().Get("prettyJSON") == "true"
	}
	return prettyJSON
}

func (response *jsonResponse) write(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	if response.code > 0 {
		w.WriteHeader(response.code)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	var bytes []byte
	var err error
	if wantPrettyJSON(r) {
		bytes, err = json.MarshalIndent(response.content, "", "    ")
	} else {
		bytes, err = json.Marshal(response.content)
	}
	if err != nil {
		return err
	}
	_, err = w.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}

func (server *Server) writeError(w http.ResponseWriter, r *http.Request, errorResponse *coreauthz.ErrorResponse) {
	if errorResponse == nil {
		return
	}
	errorResponse.WriteWithLogger(server.logger, w, r)
}
