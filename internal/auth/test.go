package auth

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"
)

var (
	ErrNoAuthHeaderIncluded         = errors.New("no authorization header included")
	ErrMalformedAuthorizationHeader = errors.New("malformed authorization header")
)

// GetAPIKey -
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}
	splitAuth := strings.Split(authHeader, " ")
	if len(splitAuth) < 2 || splitAuth[0] != "ApiKey" {
		return "", errors.New("malformed authorization header")
	}

	return splitAuth[1], nil
}

func NewTestGetAPIKey(t *testing.T) {
	testcases := map[string]struct {
		headers               http.Header
		expected_return_value string
		expected_error        error
	}{
		"Valid API Key": {
			headers: http.Header{
				"Authorization": []string{"ApiKey validapikey123"},
			},
			expected_return_value: "validapikey123",
			expected_error:        nil,
		},
		"Invalid API Key 1": {
			headers: http.Header{
				"Authorization": []string{"something validapikey123"},
			},
			expected_return_value: "",
			expected_error:        errors.New("malformed authorization header"),
		},
		"Missing API Key": {
			headers: http.Header{
				"Some-Other-Header": []string{"value"},
			},
			expected_return_value: "",
			expected_error:        errors.New("no authorization header included"),
		},
		"Empty Headers": {
			headers:               http.Header{},
			expected_return_value: "",
			expected_error:        errors.New("no authorization header included"),
		},
	}

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			result, err := GetAPIKey(tc.headers)
			if result != tc.expected_return_value {
				t.Errorf("expected '%v', got '%v'", tc.expected_return_value, result)
				if err != nil {
					log.Fatal(err)
				}
			} else if !errors.Is(err, tc.expected_error) {
				t.Errorf("Unexpected error: expected '%v', got '%v'", tc.expected_error, err)
			}
		})
	}
}
