package config

import (
	"fmt"
	"strings"
	"time"

	kycProviders "user-service/config/kyc-providers"

	"github.com/kelseyhightower/envconfig"
	"github.com/shopspring/decimal"
	"github.com/whagency/core-common/appenv"
	"github.com/whagency/core-common/cache"
)

// _minSecretLength is the floor for the HMAC keys this service signs with.
//
// Both JWT_ACCESS_SECRET and OTP_SECRET_PEPPER are HMAC-SHA256 keys, and a key
// shorter than the hash output weakens the construction -- 32 bytes is the
// standard recommendation. Length is only a proxy for entropy, so the README
// says to generate them rather than type them.
const _minSecretLength = 32

var commonsSettings CommonsSetting

type CommonsSetting struct {
	AppName             string `envconfig:"APP_NAME" required:"true"`
	Environment         string `envconfig:"APP_ENVIRONMENT" required:"true"`
	Version             string `envconfig:"APP_VERSION" default:"1.0.0"`
	TimeZone            string `envconfig:"TIME_ZONE" default:"UTC"`
	SecurityToken       string `envconfig:"SECURITY_TOKEN" required:"true"`
	SecurityTokenHeader string `default:"X-API-KEY"`
	JWTAccessSecret     string `envconfig:"JWT_ACCESS_SECRET" required:"true"`
	// JWTAdditionalIssuers names the other services that sign access tokens with
	// JWT_ACCESS_SECRET. admin-service is one: it mints a token for the admin's
	// own user id so the backoffice can open the notification websocket, and that
	// token is validated back here. This service's own APP_NAME is always
	// accepted and does not need listing.
	JWTAdditionalIssuers      []string      `envconfig:"JWT_ADDITIONAL_ISSUERS" default:""`
	RecaptchaSecretKey        string        `envconfig:"RECAPTCHA_SECRET_KEY" default:""`
	RecaptchaCheckUrl         string        `envconfig:"RECAPTCHA_CHECK_URL" default:"https://www.google.com/recaptcha/api/siteverify"`
	RecaptchaMinScore         float64       `envconfig:"RECAPTCHA_CHECK_MIN_SCORE" default:"0.4"`
	TimeoutExtCall            time.Duration `envconfig:"TIMEOUT_EXTERNAL_URL" default:"5s"`
	RestrictionServiceURL     string        `envconfig:"RESTRICTION_SERVICE_URL" required:"true"`
	RestrictionServiceGrpcURL string        `envconfig:"RESTRICTION_SERVICE_GRPC_URL" required:"true"`
	GrpcTimeout               time.Duration `envconfig:"GRPC_TIMEOUT" default:"15s"`
	OTPSecretPepper           string        `envconfig:"OTP_SECRET_PEPPER" required:"true"`
	OTPFixedCode              string        `envconfig:"OTP_FIXED_CODE" default:""`
	OTPRefreshInterval        time.Duration `envconfig:"OTP_REFRESH_INTERVAL" default:"1m"`
	GeoSkipVPNCheck           bool          `envconfig:"GEO_SKIP_VPN_CHECK" default:"false"`
	HTTPClientDumpAll         bool          `envconfig:"HTTP_CLIENT_DUMP_ALL" default:"false"`
	LoginMaxFailedAttempts    uint16        `envconfig:"LOGIN_MAX_FAILED_ATTEMPTS" default:"5"`
	LoginLockDuration         time.Duration `envconfig:"LOGIN_LOCK_DURATION" default:"15m"`

	DateFormat           string
	OTPSecretPepperBytes []byte
	JWTAccessSecretBytes []byte
}

// IsProduction checks if the environment is production
func (CommonsSetting) IsProduction() bool {
	return appenv.IsProduction(commonsSettings.Environment)
}

func Commons() CommonsSetting {
	return commonsSettings
}

// Init loads the configurations
func Init() error {
	if err := loadCommonConfig(); err != nil {
		return fmt.Errorf("[config:Init]%w", err)
	}

	if err := loadLoggerConfig(); err != nil {
		return fmt.Errorf("[config:Init]%w", err)
	}

	if err := loadTracerConfig(); err != nil {
		return fmt.Errorf("[config:Init]%w", err)
	}

	if err := loadHTTPConfig(); err != nil {
		return fmt.Errorf("[config:Init]%w", err)
	}

	if err := loadGRPCConfig(); err != nil {
		return fmt.Errorf("[config:Init]%w", err)
	}

	if err := loadQueueConfig(); err != nil {
		return fmt.Errorf("[config:Init]%w", err)
	}

	if err := loadDBConfig(); err != nil {
		return fmt.Errorf("[config:Init]%w", err)
	}

	if err := loadDBLoggerConfig(); err != nil {
		return fmt.Errorf("[config:Init]%w", err)
	}

	if err := cache.LoadCacheConfig(); err != nil {
		return fmt.Errorf("[config:Init]%w", err)
	}

	if err := loadProvidersKYCConfig(); err != nil {
		return fmt.Errorf("[config:Init]%w", err)
	}

	if err := loadCronConfig(); err != nil {
		return fmt.Errorf("[config:Init]%w", err)
	}

	// decimal library configuration for parsing the float values
	decimal.MarshalJSONWithoutQuotes = true

	return nil
}

// InitForDBMigration initializes only the DB configurations for migration purpose
func InitForDBMigration() error {
	if err := loadCommonConfig(); err != nil {
		return fmt.Errorf("[config:Init]%w", err)
	}

	if err := loadDBConfig(); err != nil {
		return fmt.Errorf("[config:InitForDBMigration]%w", err)
	}

	return nil
}

// loadCommonConfig loads the common configurations
func loadCommonConfig() error {
	if err := envconfig.Process("", &commonsSettings); err != nil {
		return fmt.Errorf("[loadCommonConfig][err: %w]", err)
	}

	if err := appenv.ValidateAppName(commonsSettings.AppName); err != nil {
		return fmt.Errorf("[loadCommonConfig][err: %w]", err)
	}

	normalizedEnvironment, err := appenv.Normalize(commonsSettings.Environment)
	if err != nil {
		return fmt.Errorf("[loadCommonConfig][err: %w]", err)
	}
	commonsSettings.Environment = normalizedEnvironment

	securityToken, err := appenv.NormalizeSecurityToken(commonsSettings.SecurityToken)
	if err != nil {
		return fmt.Errorf("[loadCommonConfig][err: %w]", err)
	}
	commonsSettings.SecurityToken = securityToken

	// envconfig's required tag treats an empty value as set, and the constructors
	// downstream only check for empty -- so "secret" passed every gate and gave
	// HS256 six bytes of key. Anyone holding one issued token could brute force
	// that offline and then mint their own.
	if err := validateSecret("JWT_ACCESS_SECRET", commonsSettings.JWTAccessSecret); err != nil {
		return fmt.Errorf("[loadCommonConfig]%w", err)
	}
	if err := validateSecret("OTP_SECRET_PEPPER", commonsSettings.OTPSecretPepper); err != nil {
		return fmt.Errorf("[loadCommonConfig]%w", err)
	}

	commonsSettings.OTPFixedCode = strings.TrimSpace(commonsSettings.OTPFixedCode)
	if commonsSettings.OTPFixedCode != "" && !appenv.IsDevLike(commonsSettings.Environment) {
		return fmt.Errorf("[loadCommonConfig][err: OTP_FIXED_CODE is allowed only for local/dev/test environments]")
	}

	// The dump writes whole outbound requests and responses to the log, headers
	// included -- the AMLBot API token and the reCAPTCHA secret among them. It
	// used to switch itself on with LOG_LEVEL=debug, which is a level an operator
	// may reasonably reach for in production. Same guard as OTP_FIXED_CODE.
	if commonsSettings.HTTPClientDumpAll && !appenv.IsDevLike(commonsSettings.Environment) {
		return fmt.Errorf("[loadCommonConfig][err: HTTP_CLIENT_DUMP_ALL is allowed only for local/dev/test environments]")
	}

	// A lock that never releases would let anyone who knows an address keep the
	// owner out for good, so a zero window is refused rather than treated as
	// "forever". Zero attempts would lock every account on its first typo.
	if commonsSettings.LoginMaxFailedAttempts == 0 {
		return fmt.Errorf("[loadCommonConfig][err: LOGIN_MAX_FAILED_ATTEMPTS must be greater than 0]")
	}
	if commonsSettings.LoginLockDuration <= 0 {
		return fmt.Errorf("[loadCommonConfig][err: LOGIN_LOCK_DURATION must be greater than 0]")
	}

	commonsSettings.DateFormat = time.RFC3339

	commonsSettings.OTPSecretPepperBytes = []byte(commonsSettings.OTPSecretPepper)
	commonsSettings.JWTAccessSecretBytes = []byte(commonsSettings.JWTAccessSecret)

	return nil
}

// validateSecret rejects a signing key too short to be worth having.
func validateSecret(name, value string) error {
	if len(strings.TrimSpace(value)) < _minSecretLength {
		return fmt.Errorf(
			"[validateSecret][err: %s must be at least %d characters; generate one with `openssl rand -base64 32`]",
			name, _minSecretLength,
		)
	}

	return nil
}

// loadProvidersKYCConfig loads the kyc providers configuration from the environment variables
func loadProvidersKYCConfig() error {
	if err := kycProviders.LoadAMLBotConfig(); err != nil {
		return err
	}

	return nil
}
