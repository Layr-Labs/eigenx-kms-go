package config

import (
	"strings"
	"testing"
)

func Test_RedisConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     RedisConfig
		wantErr string // substring; empty means no error
	}{
		{
			name:    "empty address",
			cfg:     RedisConfig{Password: "p"},
			wantErr: "redis address cannot be empty",
		},
		{
			name:    "DB out of range (negative)",
			cfg:     RedisConfig{Address: "localhost:6379", Password: "p", DB: -1},
			wantErr: "redis DB must be between 0 and 15",
		},
		{
			name:    "DB out of range (too high)",
			cfg:     RedisConfig{Address: "localhost:6379", Password: "p", DB: 16},
			wantErr: "redis DB must be between 0 and 15",
		},
		{
			name:    "empty password without AllowNoAuth is rejected",
			cfg:     RedisConfig{Address: "localhost:6379"},
			wantErr: "redis password is required",
		},
		{
			name: "empty password with AllowNoAuth is accepted",
			cfg:  RedisConfig{Address: "localhost:6379", AllowNoAuth: true},
		},
		{
			name:    "TLS cert without key is rejected",
			cfg:     RedisConfig{Address: "localhost:6379", Password: "p", TLSCertPath: "/tmp/c.pem"},
			wantErr: "TLS client cert and key must be set together",
		},
		{
			name:    "TLS key without cert is rejected",
			cfg:     RedisConfig{Address: "localhost:6379", Password: "p", TLSKeyPath: "/tmp/k.pem"},
			wantErr: "TLS client cert and key must be set together",
		},
		{
			name:    "InsecureSkipVerify without UseTLS is rejected",
			cfg:     RedisConfig{Address: "localhost:6379", Password: "p", TLSInsecureSkipVerify: true},
			wantErr: "tls_insecure_skip_verify has no effect without use_tls=true",
		},
		{
			name: "valid TLS config",
			cfg:  RedisConfig{Address: "localhost:6379", Password: "p", UseTLS: true},
		},
		{
			name: "valid mTLS config",
			cfg: RedisConfig{
				Address: "localhost:6379", Password: "p",
				UseTLS: true, TLSCertPath: "/c", TLSKeyPath: "/k",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
