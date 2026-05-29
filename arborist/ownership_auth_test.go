package arborist

import (
	"io"
	"log"
	"net/http"
	"testing"
	"time"
)

type testJWTDecoder struct{}

func (testJWTDecoder) Decode(token string) (*map[string]interface{}, error) {
	claims := map[string]interface{}{
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"context": map[string]interface{}{
			"user": map[string]interface{}{
				"name": "Owner@Example.org",
			},
		},
	}
	return &claims, nil
}

func TestUsernameFromBearerRequiresRevproxyBearerScheme(t *testing.T) {
	server := NewServer().
		WithJWTApp(testJWTDecoder{}).
		WithLogger(log.New(io.Discard, "", 0))

	t.Run("accepts lowercase revproxy bearer scheme", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/ownership/resource", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "bearer test-token")

		username, errResponse := server.usernameFromBearer(req)
		if errResponse != nil {
			t.Fatalf("expected lowercase bearer token to decode, got error: %s", errResponse.HTTPError.Message)
		}
		if username != "owner@example.org" {
			t.Fatalf("expected normalized username owner@example.org, got %s", username)
		}
	})

	t.Run("rejects uppercase bearer scheme", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/ownership/resource", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer test-token")

		_, errResponse := server.usernameFromBearer(req)
		if errResponse == nil {
			t.Fatal("expected uppercase bearer token scheme to be rejected")
		}
		if errResponse.HTTPError.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", errResponse.HTTPError.Code)
		}
	})
}
