package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_RedisConfig_Validate(t *testing.T) {
	tests := []struct {
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func Test_validateRedisForChain(t *testing.T) {
	prodCfg := func(rc RedisConfig) *PersistenceConfig {
		return &PersistenceConfig{Type: "redis", RedisConfig: &rc}
	}

	tests := []struct {
		name    string
		pc      *PersistenceConfig
		chainID ChainId
		wantErr string
	}{
		{
			name:    "non-redis persistence is a no-op",
			pc:      &PersistenceConfig{Type: "badger"},
			chainID: ChainId_EthereumMainnet,
		},
		{
			name:    "non-production chain is a no-op",
			pc:      prodCfg(RedisConfig{Address: "localhost:6379"}),
			chainID: ChainId_EthereumSepolia,
		},
		{
			name:    "production chain requires TLS",
			pc:      prodCfg(RedisConfig{Address: "localhost:6379", Password: "p"}),
			chainID: ChainId_EthereumMainnet,
			wantErr: "--redis-use-tls is required on production chain",
		},
		{
			name:    "production chain refuses AllowNoAuth",
			pc:      prodCfg(RedisConfig{Address: "localhost:6379", UseTLS: true, AllowNoAuth: true}),
			chainID: ChainId_EthereumMainnet,
			wantErr: "--redis-allow-no-auth is not permitted on production chain",
		},
		{
			name:    "production chain refuses InsecureSkipVerify",
			pc:      prodCfg(RedisConfig{Address: "localhost:6379", Password: "p", UseTLS: true, TLSInsecureSkipVerify: true}),
			chainID: ChainId_EthereumMainnet,
			wantErr: "--redis-tls-insecure-skip-verify is not permitted on production chain",
		},
		{
			name:    "production chain accepts TLS + auth",
			pc:      prodCfg(RedisConfig{Address: "localhost:6379", Password: "p", UseTLS: true}),
			chainID: ChainId_EthereumMainnet,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chainName := ChainIdToName[tt.chainID]
			err := validateRedisForChain(tt.pc, tt.chainID, chainName)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
