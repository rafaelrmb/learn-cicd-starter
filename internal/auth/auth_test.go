package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantAPIKey string
		wantErr    bool
	}{
		{
			name: "empty Authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			wantAPIKey: "",
			wantErr:    false,
		},
		{
			name: "malformed Authorization header (missing 'ApiKey' prefix)",
			headers: http.Header{
				"Authorization": []string{"InvalidPrefix apiKeyValue"},
			},
			wantAPIKey: "",
			wantErr:    true,
		},
		{
			name: "malformed Authorization header (missing API key value)",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantAPIKey: "",
			wantErr:    true,
		},
		{
			name: "valid Authorization header with API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey apiKeyValue"},
			},
			wantAPIKey: "apiKeyValue",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if apiKey != tt.wantAPIKey {
				t.Errorf("GetAPIKey() apiKey = %v, want %v", apiKey, tt.wantAPIKey)
			}
		})
	}
}