package config

import (
	"strings"
	"testing"
)

// The dump writes provider credentials into the log, so the environment guard is
// the thing standing between a convenience flag and a production leak. It is the
// same guard OTP_FIXED_CODE has, and it deserves the same test.
func TestLoadCommonConfigRejectsHTTPDumpOutsideDev(t *testing.T) {
	setRequiredCommonEnv(t)
	t.Setenv("APP_ENVIRONMENT", "production")
	t.Setenv("HTTP_CLIENT_DUMP_ALL", "true")

	err := loadCommonConfig()
	if err == nil {
		t.Fatal("expected production to reject HTTP_CLIENT_DUMP_ALL")
	}
	if !strings.Contains(err.Error(), "HTTP_CLIENT_DUMP_ALL") {
		t.Fatalf("expected the error to name the offending setting, got %v", err)
	}
}

func TestLoadCommonConfigAllowsHTTPDumpLocally(t *testing.T) {
	setRequiredCommonEnv(t)
	t.Setenv("APP_ENVIRONMENT", "local")
	t.Setenv("HTTP_CLIENT_DUMP_ALL", "true")

	if err := loadCommonConfig(); err != nil {
		t.Fatalf("expected local to allow the dump, got %v", err)
	}
	if !Commons().HTTPClientDumpAll {
		t.Fatal("expected HTTPClientDumpAll to be set")
	}
}

func TestLoadCommonConfigDefaultsHTTPDumpOff(t *testing.T) {
	setRequiredCommonEnv(t)
	t.Setenv("APP_ENVIRONMENT", "production")

	if err := loadCommonConfig(); err != nil {
		t.Fatalf("loadCommonConfig: %v", err)
	}
	if Commons().HTTPClientDumpAll {
		t.Fatal("the dump must be off unless asked for")
	}
}

// setRequiredCommonEnv fills in the values envconfig marks required, so each test
// only has to state the setting it is actually about.
func setRequiredCommonEnv(t *testing.T) {
	t.Helper()

	for key, value := range map[string]string{
		"APP_NAME":                     "user-service",
		"SECURITY_TOKEN":               "0123456789abcdef0123456789abcdef",
		"JWT_ACCESS_SECRET":            "0123456789abcdef0123456789abcdef",
		"OTP_SECRET_PEPPER":            "0123456789abcdef0123456789abcdef",
		"RESTRICTION_SERVICE_URL":      "http://localhost:8083",
		"RESTRICTION_SERVICE_GRPC_URL": "localhost:50054",
	} {
		t.Setenv(key, value)
	}
}

// envconfig's required tag treats an empty value as set, and the constructors
// downstream only check for empty. So "secret" passed every gate and gave HS256
// six bytes of key -- brute-forceable offline from any token the service had
// ever issued, after which an attacker mints their own.
func TestLoadCommonConfigRejectsShortSecrets(t *testing.T) {
	tests := []struct {
		name    string
		envVar  string
		value   string
		wantErr bool
	}{
		{name: "short jwt secret", envVar: "JWT_ACCESS_SECRET", value: "secret", wantErr: true},
		{name: "short otp pepper", envVar: "OTP_SECRET_PEPPER", value: "pepper", wantErr: true},
		{name: "empty jwt secret", envVar: "JWT_ACCESS_SECRET", value: "", wantErr: true},
		{name: "whitespace is not length", envVar: "JWT_ACCESS_SECRET", value: "                                    ", wantErr: true},
		{name: "one short of the floor", envVar: "JWT_ACCESS_SECRET", value: "0123456789abcdef0123456789abcde", wantErr: true},
		{name: "exactly the floor", envVar: "JWT_ACCESS_SECRET", value: "0123456789abcdef0123456789abcdef", wantErr: false},
		{name: "a generated key", envVar: "OTP_SECRET_PEPPER", value: "sT9k2Lm4Qw8rZx1Vb6Nc3Yh7Jf0Pd5Ag2Ke8Ru4Tz6=", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRequiredCommonEnv(t)
			t.Setenv("APP_ENVIRONMENT", "local")
			t.Setenv(tt.envVar, tt.value)

			err := loadCommonConfig()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected %s=%q to be rejected", tt.envVar, tt.value)
				}
				if !strings.Contains(err.Error(), tt.envVar) {
					t.Fatalf("the error must name the offending variable, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected %s=%q to be accepted, got %v", tt.envVar, tt.value, err)
			}
		})
	}
}

// The floor is not arbitrary: both values are HMAC-SHA256 keys, and a key shorter
// than the hash output weakens the construction.
func TestSecretFloorMatchesTheHashOutput(t *testing.T) {
	const sha256OutputBytes = 32

	if _minSecretLength < sha256OutputBytes {
		t.Fatalf("_minSecretLength is %d but an HMAC-SHA256 key should be at least %d",
			_minSecretLength, sha256OutputBytes)
	}
}

// JWT_ADDITIONAL_ISSUERS names the other services that sign with the same key.
// Unset is the safe default: only this service's own APP_NAME is then accepted.
func TestLoadCommonConfigParsesAdditionalIssuers(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{name: "unset accepts only our own", value: "", want: nil},
		{name: "one issuer", value: "admin-service", want: []string{"admin-service"}},
		{name: "several", value: "admin-service,metrics-service", want: []string{"admin-service", "metrics-service"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRequiredCommonEnv(t)
			t.Setenv("APP_ENVIRONMENT", "local")
			t.Setenv("JWT_ADDITIONAL_ISSUERS", tt.value)

			if err := loadCommonConfig(); err != nil {
				t.Fatalf("loadCommonConfig: %v", err)
			}

			got := Commons().JWTAdditionalIssuers
			if len(got) != len(tt.want) {
				t.Fatalf("JWTAdditionalIssuers = %#v, want %#v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("JWTAdditionalIssuers = %#v, want %#v", got, tt.want)
				}
			}
		})
	}
}
