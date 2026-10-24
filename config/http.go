package config

import (
	"fmt"
	"time"

	"github.com/kelseyhightower/envconfig"
)

const (
	_maxConnsPerHost     = 100
	_maxIdleConns        = 100
	_maxIdleConnsPerHost = 100
	_maxRetries          = 2
)

var httpSettings HTTPSettings

type HTTPSettings struct {
	Port                 string          `envconfig:"PORT" default:"8000"`
	ServerTimeout        time.Duration   `envconfig:"SERVER_TIMEOUT" default:"5s"`
	ReadTimeout          time.Duration   `envconfig:"SERVER_READ_TIMEOUT" default:"5s"`
	ReadHeaderTimeout    time.Duration   `envconfig:"SERVER_READ_HEADER_TIMEOUT" default:"5s"`
	WriteTimeout         time.Duration   `envconfig:"SERVER_WRITE_TIMEOUT" default:"5s"`
	RetryBackoffInterval []time.Duration `default:"1s,5s"`

	UserRegisterRateLimitRPS         float64       `envconfig:"USER_REGISTER_RATE_LIMIT_RPS" default:"0.2"`
	UserRegisterRateLimitBurst       int           `envconfig:"USER_REGISTER_RATE_LIMIT_BURST" default:"2"`
	UserRegisterRateLimitTTL         time.Duration `envconfig:"USER_REGISTER_RATE_LIMIT_TTL" default:"30m"`
	UserVerifyContactRateLimitRPS    float64       `envconfig:"USER_VERIFY_CONTACT_RATE_LIMIT_RPS" default:"0.5"`
	UserVerifyContactRateLimitBurst  int           `envconfig:"USER_VERIFY_CONTACT_RATE_LIMIT_BURST" default:"3"`
	UserVerifyContactRateLimitTTL    time.Duration `envconfig:"USER_VERIFY_CONTACT_RATE_LIMIT_TTL" default:"30m"`
	UserPasswordForgotRateLimitRPS   float64       `envconfig:"USER_PASSWORD_FORGOT_RATE_LIMIT_RPS" default:"0.2"`
	UserPasswordForgotRateLimitBurst int           `envconfig:"USER_PASSWORD_FORGOT_RATE_LIMIT_BURST" default:"2"`
	UserPasswordForgotRateLimitTTL   time.Duration `envconfig:"USER_PASSWORD_FORGOT_RATE_LIMIT_TTL" default:"30m"`
	UserPasswordResetRateLimitRPS    float64       `envconfig:"USER_PASSWORD_RESET_RATE_LIMIT_RPS" default:"0.3"`
	UserPasswordResetRateLimitBurst  int           `envconfig:"USER_PASSWORD_RESET_RATE_LIMIT_BURST" default:"3"`
	UserPasswordResetRateLimitTTL    time.Duration `envconfig:"USER_PASSWORD_RESET_RATE_LIMIT_TTL" default:"30m"`
	UserLoginRateLimitRPS            float64       `envconfig:"USER_LOGIN_RATE_LIMIT_RPS" default:"0.3"`
	UserLoginRateLimitBurst          int           `envconfig:"USER_LOGIN_RATE_LIMIT_BURST" default:"5"`
	UserLoginRateLimitTTL            time.Duration `envconfig:"USER_LOGIN_RATE_LIMIT_TTL" default:"30m"`
	UserLoginConfirmRateLimitRPS     float64       `envconfig:"USER_LOGIN_CONFIRM_RATE_LIMIT_RPS" default:"0.5"`
	UserLoginConfirmRateLimitBurst   int           `envconfig:"USER_LOGIN_CONFIRM_RATE_LIMIT_BURST" default:"5"`
	UserLoginConfirmRateLimitTTL     time.Duration `envconfig:"USER_LOGIN_CONFIRM_RATE_LIMIT_TTL" default:"30m"`
	UserTwoFAOTPResendRateLimitRPS   float64       `envconfig:"USER_TWO_FA_OTP_RESEND_RATE_LIMIT_RPS" default:"0.1"`
	UserTwoFAOTPResendRateLimitBurst int           `envconfig:"USER_TWO_FA_OTP_RESEND_RATE_LIMIT_BURST" default:"2"`
	UserTwoFAOTPResendRateLimitTTL   time.Duration `envconfig:"USER_TWO_FA_OTP_RESEND_RATE_LIMIT_TTL" default:"30m"`

	MaxConnsPerHost     int
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxRetries          int
}

// HTTP returns the HTTP settings
func HTTP() HTTPSettings {
	return httpSettings
}

// loadHTTPConfig loads the HTTP settings from the environment variables
func loadHTTPConfig() error {
	if err := envconfig.Process("", &httpSettings); err != nil {
		return fmt.Errorf("[loadHTTPConfig][err: %w]", err)
	}

	httpSettings.MaxConnsPerHost = _maxConnsPerHost
	httpSettings.MaxIdleConns = _maxIdleConns
	httpSettings.MaxIdleConnsPerHost = _maxIdleConnsPerHost
	httpSettings.MaxRetries = _maxRetries

	return nil
}
