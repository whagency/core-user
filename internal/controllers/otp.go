package controllers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"user-service/internal/domain"

	jsoniter "github.com/json-iterator/go"
	"github.com/whagency/core-common/logger"
	"github.com/whagency/core-common/queue"
	commonNotificationQueue "github.com/whagency/core-common/services/notification/queue"
)

// Defaults.
const (
	_defaultOTPLength = 6
	_defaultOTPTTL    = 5 * time.Minute
	_defaultSaltBytes = 16
	_minOTPLength     = 4
	_maxOTPLength     = 12
	_minSaltBytes     = 8
	_maxSaltBytes     = 64
	_maxTTL           = 24 * time.Hour
)

// URL-safe Base64 encoder without padding, safe for transport and JSON.
var b64 = base64.RawURLEncoding

type OTPCtrl struct {
	otpPublisher queue.Publisher
	length       int
	ttl          time.Duration
	saltSize     int
	pepper       []byte
	fixedCode    string
	clock        func() time.Time
}

// OTPOption is a functional option for configuring OTPCtrl.
type OTPOption func(ctrl *OTPCtrl)

// NewOTPController creates a new OTPCtrl with the given options.
func NewOTPController(otpPublisher queue.Publisher, pepper []byte, opts ...OTPOption) (*OTPCtrl, error) {
	if len(pepper) == 0 {
		return nil, errors.New("[OTPCtrl:NewOTPController][err: pepper must not be empty]")
	}

	h := &OTPCtrl{
		otpPublisher: otpPublisher,
		length:       _defaultOTPLength,
		ttl:          _defaultOTPTTL,
		saltSize:     _defaultSaltBytes,
		pepper:       append([]byte(nil), pepper...), // defensive copy
		clock:        func() time.Time { return time.Now().UTC() },
	}

	for _, opt := range opts {
		opt(h)
	}

	if err := h.validate(); err != nil {
		return nil, fmt.Errorf("[OTPCtrl:NewOTPController]%w", err)
	}

	return h, nil
}

// WithOTPLength sets OTP length.
func WithOTPLength(n int) OTPOption {
	return func(h *OTPCtrl) { h.length = n }
}

// WithOTPTTL sets OTP time-to-live.
func WithOTPTTL(ttl time.Duration) OTPOption {
	return func(h *OTPCtrl) { h.ttl = ttl }
}

// WithOTPSaltSize sets salt size in bytes.
func WithOTPSaltSize(n int) OTPOption {
	return func(h *OTPCtrl) { h.saltSize = n }
}

// WithOTPClock injects a custom clock function (useful for tests).
func WithOTPClock(clock func() time.Time) OTPOption {
	return func(h *OTPCtrl) {
		if clock != nil {
			h.clock = clock
		}
	}
}

// WithFixedOTPCode forces a deterministic OTP code. Intended for local/dev/test automation only.
func WithFixedOTPCode(code string) OTPOption {
	return func(h *OTPCtrl) {
		h.fixedCode = strings.TrimSpace(code)
	}
}

// validate checks if the OTPHelper configuration is valid.
func (c *OTPCtrl) validate() error {
	if c.length < _minOTPLength || c.length > _maxOTPLength {
		return fmt.Errorf("[validate][err: otp length must be in [%d,%d]]", _minOTPLength, _maxOTPLength)
	}
	if c.ttl <= 0 || c.ttl > _maxTTL {
		return fmt.Errorf("[validate][err: ttl must be in (0,%s]]", _maxTTL)
	}
	if c.saltSize < _minSaltBytes || c.saltSize > _maxSaltBytes {
		return fmt.Errorf("[validate][err: salt size must be in [%d,%d]]", _minSaltBytes, _maxSaltBytes)
	}
	if c.fixedCode != "" {
		if len(c.fixedCode) < _minOTPLength || len(c.fixedCode) > _maxOTPLength {
			return fmt.Errorf("[validate][err: fixed otp length must be in [%d,%d]]", _minOTPLength, _maxOTPLength)
		}
		for _, ch := range c.fixedCode {
			if ch < '0' || ch > '9' {
				return fmt.Errorf("[validate][err: fixed otp code must contain digits only]")
			}
		}
	}
	return nil
}

// Generate creates a new OTP token with hash and expiry.
func (c *OTPCtrl) Generate() (domain.OTPToken, error) {
	code := c.fixedCode
	if code == "" {
		var err error
		code, err = c.generateDigits()
		if err != nil {
			return domain.OTPToken{}, fmt.Errorf("[OTPCtrl:Generate]%w", err)
		}
	}

	salt, err := c.randomSalt()
	if err != nil {
		return domain.OTPToken{}, fmt.Errorf("[OTPCtrl:Generate]%w", err)
	}

	hash := c.hmacHash(salt, code)
	expiresAt := c.clock().Add(c.ttl)

	return domain.OTPToken{
		Code:      code,      // for sending to the user
		Hash:      hash,      // store in DB
		Salt:      salt,      // store in DB
		ExpiresAt: expiresAt, // store in DB
	}, nil
}

// Verify checks if the given code matches the stored hash (without expiry).
func (c *OTPCtrl) Verify(code, salt, storedHash string) bool {
	computed := c.hmacHash(salt, code)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedHash)) == 1
}

// --- internal helpers ---

// hmacHash computes HMAC-SHA256(salt:code) and encodes it in URL-safe Base64.
func (c *OTPCtrl) hmacHash(salt, code string) string {
	mac := hmac.New(sha256.New, c.pepper)
	_, _ = mac.Write([]byte(salt))
	_, _ = mac.Write([]byte{':'})
	_, _ = mac.Write([]byte(code))
	sum := mac.Sum(nil)
	return b64.EncodeToString(sum)
}

// generateDigits creates a random numeric string of the configured length.
func (c *OTPCtrl) generateDigits() (string, error) {
	digits := make([]byte, c.length)
	newMaxInt := big.NewInt(10)
	for i := range digits {
		n, err := rand.Int(rand.Reader, newMaxInt)
		if err != nil {
			return "", fmt.Errorf("[generateDigits][err: %w]", err)
		}
		digits[i] = byte('0' + n.Int64())
	}
	return string(digits), nil
}

// randomSalt generates a random salt of the configured size and encodes it in URL-safe Base64.
func (c *OTPCtrl) randomSalt() (string, error) {
	buf := make([]byte, c.saltSize)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("[randomSalt][err: %w]", err)
	}
	return b64.EncodeToString(buf), nil
}

// Send sends the OTP token to the specified destination using the configured publisher.
func (c *OTPCtrl) Send(ctx context.Context, message domain.OTPMessage) error {
	logger.LogCtx(ctx).Debugf(
		"[OTPCtrl:Send][purpose:%s][contactType:%s]",
		message.Purpose,
		message.ContactType,
	)

	payload := commonNotificationQueue.OTPMessage{
		Purpose:      string(message.Purpose),
		ContactType:  message.ContactType,
		ContactValue: message.ContactValue,
		Code:         message.Code,
		Locale:       message.Locale,
	}

	messageBytes, err := jsoniter.Marshal(payload)
	if err != nil {
		return fmt.Errorf("[OTPCtrl:Send][err: %w]", err)
	}

	if err = c.otpPublisher.Publish(ctx, queue.Message{
		MessageType: commonNotificationQueue.MessageTypeOTP,
		Data:        messageBytes,
	}); err != nil {
		return fmt.Errorf("[OTPCtrl:Send]%w", err)
	}

	return nil
}
