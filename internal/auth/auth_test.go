package auth

import (
	"errors"
	"log"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
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
			expected_error:        ErrMalformedAuthorizationHeader,
		},
		"Invalid API Key 2": {
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expected_return_value: "",
			expected_error:        ErrMalformedAuthorizationHeader,
		},
		"Invalid API Key 3": {
			headers: http.Header{
				"Authorization": []string{""},
			},
			expected_return_value: "",
			expected_error:        ErrNoAuthHeaderIncluded,
		},
		"Missing API Key": {
			headers: http.Header{
				"Some-Other-Header": []string{"value"},
			},
			expected_return_value: "",
			expected_error:        ErrNoAuthHeaderIncluded,
		},
		"Empty Headers": {
			headers:               http.Header{},
			expected_return_value: "",
			expected_error:        ErrNoAuthHeaderIncluded,
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
