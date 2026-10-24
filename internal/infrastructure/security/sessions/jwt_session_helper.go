package sessions

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"user-service/internal/domain"

	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/whagency/core-common/logger"
)

const (
	_defaultTokenAccessTTL    = 15 * time.Minute
	_defaultTokenRefreshTTL   = 30 * 24 * time.Hour
	_defaultTokenRefreshBytes = 32

	_minTokenRefreshBytes  = 16
	__maxTokenRefreshBytes = 128
)

// URL-safe Base64 without padding.
var b64 = base64.RawURLEncoding

// Public errors (good for sentinel checks).
var (
	ErrMalformedToken = errors.New("malformed JWT")
	ErrBadHeader      = errors.New("invalid JWT header")
	ErrSignature      = errors.New("signature verification failed")
	ErrExpired        = errors.New("token expired")
	ErrIssuerMismatch = errors.New("issuer mismatch")
	ErrSubjectInvalid = errors.New("invalid subject")
	ErrKeyNotFound    = errors.New("signing key not found")
	ErrMissingClaims  = errors.New("missing required claims")
	ErrUnsupportedAlg = errors.New("unsupported alg")
	ErrUnsupportedTyp = errors.New("unsupported typ")
	ErrRevoked        = errors.New("session revoked")
)

// KeyProvider returns a signing/verification key by KID.
type KeyProvider func(kid string) ([]byte, error)

// JWTSessionHelper issues/validates HS256 access JWTs + opaque refresh tokens.
type JWTSessionHelper struct {
	signingKey  []byte // Optional if using keyProvider
	keyID       string // used in header "kid" when signing
	keyProvider KeyProvider
	issuer      string
	// acceptedIssuers is what an incoming token's iss may say. It always holds
	// issuer itself; WithAdditionalIssuers adds the other services that sign
	// with the same key.
	acceptedIssuers map[string]struct{}
	accessTTL       time.Duration
	refreshTTL      time.Duration
	refreshBytes    int
	clock           func() time.Time
	revocationCache domain.CacheRepository[domain.RevokedSession]
}

// Options

type Option func(*JWTSessionHelper)

func WithIssuer(iss string) Option {
	return func(h *JWTSessionHelper) { h.issuer = iss }
}

// WithAdditionalIssuers accepts tokens minted elsewhere with the same key.
//
// admin-service signs access tokens for the admin's own user id with
// JWT_ACCESS_SECRET and hands them to the browser for the notification-service
// websocket, which validates them back through here. Those tokens are
// legitimate and say iss: admin-service, so they have to be named rather than
// waved through.
func WithAdditionalIssuers(issuers ...string) Option {
	return func(h *JWTSessionHelper) {
		for _, iss := range issuers {
			if iss = strings.TrimSpace(iss); iss != "" {
				if h.acceptedIssuers == nil {
					h.acceptedIssuers = make(map[string]struct{}, len(issuers))
				}
				h.acceptedIssuers[iss] = struct{}{}
			}
		}
	}
}

func WithKeyID(kid string) Option {
	return func(h *JWTSessionHelper) { h.keyID = kid }
}

func WithKeyProvider(p KeyProvider) Option {
	return func(h *JWTSessionHelper) { h.keyProvider = p }
}

func WithAccessTTL(d time.Duration) Option {
	return func(h *JWTSessionHelper) { h.accessTTL = d }
}

func WithRefreshTTL(d time.Duration) Option {
	return func(h *JWTSessionHelper) { h.refreshTTL = d }
}

func WithRefreshBytes(n int) Option {
	return func(h *JWTSessionHelper) {
		if n > 0 {
			h.refreshBytes = n
		}
	}
}

func WithClock(clock func() time.Time) Option {
	return func(h *JWTSessionHelper) {
		if clock != nil {
			h.clock = clock
		}
	}
}

// NewJWTSessionHelper builds a helper.
// You can either:
//  1. Provide a static signing key (HS256), or
//  2. Provide a KeyProvider (enables rotation) + keyID for signing.
func NewJWTSessionHelper(signingKey []byte, revocationCache domain.CacheRepository[domain.RevokedSession], opts ...Option) (*JWTSessionHelper, error) {
	h := &JWTSessionHelper{
		signingKey:      append([]byte(nil), signingKey...), // defensive copy
		accessTTL:       _defaultTokenAccessTTL,
		refreshTTL:      _defaultTokenRefreshTTL,
		refreshBytes:    _defaultTokenRefreshBytes,
		clock:           func() time.Time { return time.Now().UTC() },
		revocationCache: revocationCache,
	}
	for _, opt := range opts {
		opt(h)
	}
	// Its own issuer is always accepted; the option only widens the set. Leaving
	// it to configuration would mean one missing env var invalidates every
	// session this service itself signed.
	if h.issuer != "" {
		if h.acceptedIssuers == nil {
			h.acceptedIssuers = make(map[string]struct{}, 1)
		}
		h.acceptedIssuers[h.issuer] = struct{}{}
	}
	if err := h.validate(); err != nil {
		return nil, err
	}
	return h, nil
}

// validate checks the configuration.
func (h *JWTSessionHelper) validate() error {
	if len(h.signingKey) == 0 && h.keyProvider == nil {
		return fmt.Errorf("[validate][err: either signingKey or keyProvider must be provided]")
	}
	if h.accessTTL <= 0 {
		return fmt.Errorf("[validate][err: access TTL must be > 0")
	}
	if h.refreshTTL <= 0 {
		return fmt.Errorf("[validate][err: refresh TTL must be > 0")
	}
	if h.refreshBytes < _minTokenRefreshBytes || h.refreshBytes > __maxTokenRefreshBytes {
		return fmt.Errorf("[validate][err: refresh Bytes must be between %d and %d", _minTokenRefreshBytes, __maxTokenRefreshBytes)
	}
	return nil
}

// Issue mints an access JWT (HS256) and an opaque refresh token.
func (h *JWTSessionHelper) Issue(ctx context.Context, params domain.SessionIssueParams) (domain.SessionToken, error) {
	// params carries the device fingerprint, IP and user agent. Logged as
	// presence flags, matching how SessionCtrl reports the same struct.
	logger.LogCtx(ctx).Debugf(
		"[JWTSessionHelper:Issue][userID:%d][hasDeviceFingerprint:%t][hasIP:%t]",
		params.UserID,
		params.DeviceFingerprint != "",
		params.IPAddress != "",
	)

	now := h.clock()
	sid := domain.SessionID(uuid.NewString())

	claims := jwtClaims{
		Subject:           params.UserID.String(),
		SessionID:         sid.String(),
		Issuer:            h.issuer,
		IssuedAt:          now.Unix(),
		ExpiresAt:         now.Add(h.accessTTL).Unix(),
		DeviceFingerprint: params.DeviceFingerprint,
		IPAddress:         params.IPAddress,
		UserAgent:         params.UserAgent,
		Browser:           params.Browser,
	}

	accessToken, accessExp, err := h.signJWT(claims)
	if err != nil {
		return domain.SessionToken{}, fmt.Errorf("[JWTSessionHelper:Issue]%w", err)
	}

	refreshToken, err := h.generateOpaque(h.refreshBytes)
	if err != nil {
		return domain.SessionToken{}, fmt.Errorf("[JWTSessionHelper:Issue]%w", err)
	}

	return domain.SessionToken{
		SessionID:        sid,
		AccessToken:      accessToken,
		AccessExpiresAt:  time.Unix(accessExp, 0).UTC(),
		RefreshToken:     refreshToken,
		RefreshExpiresAt: now.Add(h.refreshTTL),
	}, nil
}

// jwtValidationResult holds the result of JWT validation.
type jwtValidationResult struct {
	uuid   domain.ID
	token  string
	claims jwtClaims
}

// Validate parses and verifies an access JWT, returning the authenticated session.
// Accepts either a raw JWT or a "Bearer <jwt>".
func (h *JWTSessionHelper) Validate(ctx context.Context, token string, opts domain.ValidateOptions) (domain.AuthenticatedSession, error) {
	// Never the token itself: this is a live credential, and debug logs are
	// shipped to Loki like any other. Its length is enough to tell a truncated
	// header apart from a missing one.
	logger.LogCtx(ctx).Debugf("[JWTSessionHelper:Validate][tokenLen:%d]", len(token))

	result, err := h.parseTokenAndValidate(ctx, token)
	if err != nil {
		return domain.AuthenticatedSession{}, fmt.Errorf("[JWTSessionHelper:Validate]%w", err)
	}

	// Expiry and revocation are separate questions and are asked separately.
	// Waiving one must not waive the other: a token can be legitimately expired
	// on the refresh path while the session behind it is still perfectly alive,
	// and a session can be revoked while its token is nowhere near expiring --
	// which is exactly the case a sign-out is supposed to produce.
	if !opts.AllowExpired {
		if err = h.checkExpiry(result.claims); err != nil {
			return domain.AuthenticatedSession{}, fmt.Errorf("[JWTSessionHelper:Validate]%w", err)
		}
	}

	if !opts.AllowRevoked {
		if err = h.checkRevoked(ctx, result.claims); err != nil {
			return domain.AuthenticatedSession{}, fmt.Errorf("[JWTSessionHelper:Validate]%w", err)
		}
	}

	return domain.AuthenticatedSession{
		SessionID: domain.SessionID(result.claims.SessionID),
		UserID:    result.uuid,
		IssuedAt:  time.Unix(result.claims.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(result.claims.ExpiresAt, 0).UTC(),
		SessionClientDeviceData: domain.SessionClientDeviceData{
			DeviceFingerprint: result.claims.DeviceFingerprint,
			IPAddress:         result.claims.IPAddress,
			UserAgent:         result.claims.UserAgent,
			Browser:           result.claims.Browser,
		},
		RawToken: result.token,
	}, nil
}

// parseTokenAndValidate parses the JWT and verifies its signature.
func (h *JWTSessionHelper) parseTokenAndValidate(ctx context.Context, token string) (jwtValidationResult, error) {
	logger.LogCtx(ctx).Debugf("[JWTSessionHelper:parseTokenAndValidate][tokenLen:%d]", len(token))

	// Strip "Bearer " prefix if present.
	raw := stripBearer(token)

	headerJSON, payloadJSON, sig, signingInput, err := splitAndDecode(raw)
	if err != nil {
		return jwtValidationResult{}, fmt.Errorf("[parseTokenAndValidate]%w", err)
	}

	// Header
	var header jwtHeader
	if err = jsoniter.Unmarshal(headerJSON, &header); err != nil {
		return jwtValidationResult{}, fmt.Errorf("[parseTokenAndValidate][err: %w]", ErrBadHeader)
	}
	if header.Alg != "HS256" {
		return jwtValidationResult{}, fmt.Errorf("[parseTokenAndValidate][alg: %s][err: %w]", header.Alg, ErrUnsupportedAlg)
	}
	if header.Typ != "JWT" && header.Typ != "" {
		return jwtValidationResult{}, fmt.Errorf("[parseTokenAndValidate][err: %w]", ErrUnsupportedTyp)
	}

	// Claims
	var claims jwtClaims
	if err = jsoniter.Unmarshal(payloadJSON, &claims); err != nil {
		return jwtValidationResult{}, fmt.Errorf("[parseTokenAndValidate][err: %w]", ErrMalformedToken)
	}
	if claims.IssuedAt == 0 || claims.ExpiresAt == 0 || claims.Subject == "" || claims.SessionID == "" {
		return jwtValidationResult{}, fmt.Errorf("[parseTokenAndValidate][err: %w]", ErrMissingClaims)
	}

	// A configured issuer is a requirement, not a preference. This used to skip
	// the check when the claim was absent, so a token with no iss at all was
	// accepted by whoever held the key -- and the key is shared with
	// admin-service, which mints tokens for arbitrary user ids. What the check
	// buys with a shared symmetric key is provenance rather than authorization:
	// any holder of the key can write any iss it likes. Telling the issuers
	// apart for real needs a key per issuer, which the kid/keyProvider seam
	// already allows and nothing configures yet.
	if h.issuer != "" {
		if claims.Issuer == "" {
			return jwtValidationResult{}, fmt.Errorf("[parseTokenAndValidate][iss: absent][err: %w]", ErrIssuerMismatch)
		}
		if _, ok := h.acceptedIssuers[claims.Issuer]; !ok {
			return jwtValidationResult{}, fmt.Errorf("[parseTokenAndValidate][iss: %s][err: %w]", claims.Issuer, ErrIssuerMismatch)
		}
	}

	// Verify signature.
	key, err := h.verificationKey(header.KID)
	if err != nil {
		return jwtValidationResult{}, fmt.Errorf("[parseTokenAndValidate]%w", err)
	}
	expected := computeHMAC([]byte(signingInput), key)
	if subtle.ConstantTimeCompare(expected, sig) != 1 {
		return jwtValidationResult{}, fmt.Errorf("[parseTokenAndValidate]%w", ErrSignature)
	}

	// Parse subject as user ID.
	uuid, err := domain.NewIDFromString(claims.Subject)
	if err != nil {
		return jwtValidationResult{}, fmt.Errorf("[parseTokenAndValidate][subject: %s][err: %w]", claims.Subject, ErrSubjectInvalid)
	}

	return jwtValidationResult{
		uuid:   uuid,
		token:  raw,
		claims: claims,
	}, nil
}

// checkExpiry rejects a token past its exp claim.
func (h *JWTSessionHelper) checkExpiry(claims jwtClaims) error {
	if h.clock().Unix() >= claims.ExpiresAt {
		return fmt.Errorf("[checkExpiry][err: %w]", ErrExpired)
	}

	return nil
}

// checkRevoked rejects a token whose session has been revoked.
//
// A cache lookup by session id: cheap enough that skipping it was never a
// performance decision, only an accident of sharing a function with the expiry
// check. A cache failure is an error rather than a pass -- not knowing whether a
// session was revoked is not the same as knowing it was not.
func (h *JWTSessionHelper) checkRevoked(ctx context.Context, claims jwtClaims) error {
	revoked, err := h.revocationCache.Exists(ctx, claims.SessionID)
	if err != nil {
		return fmt.Errorf("[checkRevoked]%w", err)
	}

	if revoked {
		return fmt.Errorf("[checkRevoked][err: %w]", ErrRevoked)
	}

	return nil
}

// --- signing / verifying internals ---

// signingKeyAndHeader returns the signing key and JWT header to use when signing.
func (h *JWTSessionHelper) signingKeyAndHeader() ([]byte, jwtHeader, error) {
	if len(h.signingKey) > 0 {
		return h.signingKey, jwtHeader{Alg: "HS256", Typ: "JWT", KID: h.keyID}, nil
	}

	if h.keyProvider == nil {
		return nil, jwtHeader{}, fmt.Errorf("[signingKeyAndHeader][err: no signing key or provider available]")
	}

	if h.keyID == "" {
		return nil, jwtHeader{}, fmt.Errorf("[signingKeyAndHeader][err: keyID is required when signing with keyProvider]")
	}

	key, err := h.keyProvider(h.keyID)
	if err != nil {
		return nil, jwtHeader{}, fmt.Errorf("[signingKeyAndHeader]%w", err)
	}

	if len(key) == 0 {
		return nil, jwtHeader{}, fmt.Errorf("[signingKeyAndHeader]%w", ErrKeyNotFound)
	}

	return key, jwtHeader{Alg: "HS256", Typ: "JWT", KID: h.keyID}, nil
}

// verificationKey returns the verification key for the given KID.
func (h *JWTSessionHelper) verificationKey(kid string) ([]byte, error) {
	if len(h.signingKey) > 0 {
		return h.signingKey, nil
	}

	if h.keyProvider == nil {
		return nil, fmt.Errorf("[verificationKey][err: no key provider for verification]")
	}

	key, err := h.keyProvider(kid)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, fmt.Errorf("[verificationKey][err: %w]", ErrKeyNotFound)
		}
		return nil, fmt.Errorf("[verificationKey][err: %w]", err)
	}

	if len(key) == 0 {
		return nil, fmt.Errorf("[verificationKey][err: %w]", ErrKeyNotFound)
	}
	return key, nil
}

// signJWT creates a signed JWT string from the given claims.
func (h *JWTSessionHelper) signJWT(c jwtClaims) (token string, expUnix int64, err error) {
	key, header, err := h.signingKeyAndHeader()
	if err != nil {
		return "", 0, fmt.Errorf("[signJWT]%w", err)
	}

	if c.ExpiresAt == 0 {
		return "", 0, fmt.Errorf("[signJWT]%w", ErrMissingClaims)
	}

	headerJSON, err := jsoniter.Marshal(header)
	if err != nil {
		return "", 0, fmt.Errorf("[signJWT]%w", err)
	}

	payloadJSON, err := jsoniter.Marshal(c)
	if err != nil {
		return "", 0, fmt.Errorf("[signJWT]%w", err)
	}

	encHeader := b64.EncodeToString(headerJSON)
	encPayload := b64.EncodeToString(payloadJSON)
	signingInput := encHeader + "." + encPayload

	sig := computeHMAC([]byte(signingInput), key)
	encSig := b64.EncodeToString(sig)

	return signingInput + "." + encSig, c.ExpiresAt, nil
}

// HashRefreshToken returns the hex-encoded SHA-256 of a refresh token: the value
// that goes to the database, so a leaked dump yields hashes rather than working
// credentials.
//
// A plain hash is the right instrument here and bcrypt would be the wrong one.
// The token is generateOpaque's output — refreshBytes of crypto/rand, at least
// 128 bits — so there is no guessable space to slow an attacker down in, and
// this runs on every refresh. That is the opposite of a password, which is
// low-entropy and hashed rarely.
func (h *JWTSessionHelper) HashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// generateOpaque creates a URL-safe opaque token of n random bytes.
func (h *JWTSessionHelper) generateOpaque(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("[generateOpaque]%w", err)
	}
	return b64.EncodeToString(buf), nil
}

// computeHMAC computes HMAC-SHA256 of input using the given key.
func computeHMAC(input, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(input)
	return mac.Sum(nil)
}

// --- wire helpers ---

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	KID string `json:"kid,omitempty"`
}

type jwtClaims struct {
	Subject           string `json:"sub"`
	SessionID         string `json:"sid"`
	Issuer            string `json:"iss,omitempty"`
	IssuedAt          int64  `json:"iat"`
	ExpiresAt         int64  `json:"exp"`
	DeviceFingerprint string `json:"dfp,omitempty"`
	IPAddress         string `json:"ip,omitempty"`
	UserAgent         string `json:"ua,omitempty"`
	Browser           string `json:"browser,omitempty"`
}

// stripBearer removes a "Bearer " prefix if present (case-insensitive) and trims spaces.
func stripBearer(s string) string {
	if s == "" {
		return s
	}
	// case-insensitive "Bearer "
	if len(s) > 7 && strings.EqualFold(s[:7], "Bearer ") {
		return strings.TrimSpace(s[7:])
	}
	return strings.TrimSpace(s)
}

// splitAndDecode splits a JWT into its three parts and base64-decodes them.
func splitAndDecode(raw string) (headerJSON, payloadJSON, sig []byte, signingInput string, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, nil, nil, "", fmt.Errorf("[splitAndDecode]: %w", ErrMalformedToken)
	}

	headerSeg, payloadSeg, sigSeg := parts[0], parts[1], parts[2]
	signingInput = headerSeg + "." + payloadSeg

	headerJSON, err = b64.DecodeString(headerSeg)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("[splitAndDecode]%w", err)
	}

	payloadJSON, err = b64.DecodeString(payloadSeg)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("[splitAndDecode]%w", err)
	}

	sig, err = b64.DecodeString(sigSeg)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("[splitAndDecode]%w", err)
	}
	return
}
