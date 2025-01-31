package auth

import (
	"errors"
	"net/http"
	"strings"
)

var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")
var ErrNoAuthKeyInHeader = errors.New("malformed authorization header")

// GetAPIKey -
func GetAPIKey(headers http.Header) (string, error) {
	authHeader, exists := headers["Authorization"]
	if !exists {
		return "", ErrNoAuthHeaderIncluded
	}
	if len(authHeader) == 0 {
		return "", ErrNoAuthKeyInHeader
	}
	splitAuth := strings.Split(authHeader[0], " ")
	if len(splitAuth) < 2 || splitAuth[0] != "ApiKey" {
		return "", ErrNoAuthKeyInHeader
	}

	return splitAuth[1], nil
}
