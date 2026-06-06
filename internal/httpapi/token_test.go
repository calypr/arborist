package httpapi

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	coreauthz "github.com/calypr/arborist/internal/authz/core"
	"github.com/stretchr/testify/assert"
)

type stubJWTDecoder struct {
	claims map[string]interface{}
}

func (decoder *stubJWTDecoder) Decode(token string) (*map[string]interface{}, error) {
	return &decoder.claims, nil
}

func TestUsernameFromBearer(t *testing.T) {
	server := &Server{
		logger: coreauthz.NewLogHandler(log.New(io.Discard, "", 0)),
		jwtApp: &stubJWTDecoder{
			claims: map[string]interface{}{
				"scope": []interface{}{"openid"},
				"exp":   float64(4102444800),
				"sub":   "0",
				"context": map[string]interface{}{
					"user": map[string]interface{}{
						"name": "User@Example.org",
					},
				},
			},
		},
	}

	t.Run("accepts standard Bearer scheme", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ownership/resource", nil)
		req.Header.Set("Authorization", "Bearer fake-token")

		username, errResponse := server.usernameFromBearer(req)

		assert.Nil(t, errResponse)
		assert.Equal(t, "user@example.org", username)
	})

	t.Run("accepts lowercase bearer scheme", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ownership/resource", nil)
		req.Header.Set("Authorization", "bearer fake-token")

		username, errResponse := server.usernameFromBearer(req)

		assert.Nil(t, errResponse)
		assert.Equal(t, "user@example.org", username)
	})

	t.Run("rejects non bearer scheme", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ownership/resource", nil)
		req.Header.Set("Authorization", "Basic fake-token")

		username, errResponse := server.usernameFromBearer(req)

		assert.Equal(t, "", username)
		if assert.NotNil(t, errResponse) {
			assert.Equal(t, http.StatusUnauthorized, errResponse.HTTPError.Code)
			assert.Equal(t, "Authorization header must use bearer token scheme", errResponse.HTTPError.Message)
		}
	})
}
