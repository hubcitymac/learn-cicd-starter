package auth

import (
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	goodHeader := make(http.Header)
	emptyHeader := make(http.Header)
	badHeader := make(http.Header)
	emptyKey := make(http.Header)
	badKey := make(http.Header)
	goodHeader.Set("Authorization", "ApiKey APIKEY")
	emptyKey.Set("Authorization", "")
	badHeader.Set("Wrong Header", "ApiKey APIKEY")
	badKey.Set("Authorization", "apikey APIKEY")
	tests := []struct {
		name  string
		input http.Header
		want  struct {
			apikey string
			err    error
		}
	}{
		{
			name:  "Good Header",
			input: goodHeader,
			want: struct {
				apikey string
				err    error
			}{
				apikey: "APIKEY",
				err:    nil,
			},
		},
		{
			name:  "Bad Header",
			input: badHeader,
			want: struct {
				apikey string
				err    error
			}{
				apikey: "",
				err:    auth.ErrNoAuthHeaderIncluded,
			},
		},
		{
			name:  "Empty Header",
			input: emptyHeader,
			want: struct {
				apikey string
				err    error
			}{
				apikey: "",
				err:    auth.ErrNoAuthHeaderIncluded,
			},
		},
		{
			name:  "Empty Key",
			input: emptyKey,
			want: struct {
				apikey string
				err    error
			}{
				apikey: "",
				err:    auth.ErrNoAuthKeyInHeader,
			},
		},
		{
			name:  "Bad Key",
			input: badKey,
			want: struct {
				apikey string
				err    error
			}{
				apikey: "",
				err:    auth.ErrNoAuthKeyInHeader,
			},
		},
	}
	for _, tc := range tests {
		apiKey, err := auth.GetAPIKey(tc.input)
		if apiKey != tc.want.apikey {
			t.Errorf("%s: expected apikey %v, got %v", tc.name, tc.want.apikey, apiKey)
		}
		if (tc.want.err == nil) != (err == nil) {
			t.Errorf("%s: expected error %v, got %v", tc.name, tc.want.err, err)
		}
		if tc.want.err != nil && err != nil && tc.want.err.Error() != err.Error() {
			t.Errorf("%s: expected error %v, got %v", tc.name, tc.want.err, err)
		}
	}
}
