package config

import (
	"testing"
	"time"
)

func TestLoadHTTPConfigLoadsPublicRateLimitOverrides(t *testing.T) {
	t.Setenv("USER_REGISTER_RATE_LIMIT_RPS", "7")
	t.Setenv("USER_REGISTER_RATE_LIMIT_BURST", "21")
	t.Setenv("USER_REGISTER_RATE_LIMIT_TTL", "45m")
	t.Setenv("USER_LOGIN_RATE_LIMIT_RPS", "3")
	t.Setenv("USER_LOGIN_RATE_LIMIT_BURST", "9")
	t.Setenv("USER_LOGIN_RATE_LIMIT_TTL", "15m")

	if err := loadHTTPConfig(); err != nil {
		t.Fatalf("loadHTTPConfig() error = %v", err)
	}

	cfg := HTTP()
	if cfg.UserRegisterRateLimitRPS != 7 {
		t.Fatalf("UserRegisterRateLimitRPS = %v, want 7", cfg.UserRegisterRateLimitRPS)
	}
	if cfg.UserRegisterRateLimitBurst != 21 {
		t.Fatalf("UserRegisterRateLimitBurst = %v, want 21", cfg.UserRegisterRateLimitBurst)
	}
	if cfg.UserRegisterRateLimitTTL != 45*time.Minute {
		t.Fatalf("UserRegisterRateLimitTTL = %v, want 45m", cfg.UserRegisterRateLimitTTL)
	}
	if cfg.UserLoginRateLimitRPS != 3 {
		t.Fatalf("UserLoginRateLimitRPS = %v, want 3", cfg.UserLoginRateLimitRPS)
	}
	if cfg.UserLoginRateLimitBurst != 9 {
		t.Fatalf("UserLoginRateLimitBurst = %v, want 9", cfg.UserLoginRateLimitBurst)
	}
	if cfg.UserLoginRateLimitTTL != 15*time.Minute {
		t.Fatalf("UserLoginRateLimitTTL = %v, want 15m", cfg.UserLoginRateLimitTTL)
	}
}
