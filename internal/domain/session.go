package domain

import (
	"context"
	"time"

	appErrors "github.com/whagency/core-common/errorsx"
)

type SessionClientDeviceData struct {
	DeviceFingerprint string
	IPAddress         string
	UserAgent         string
	Browser           string
	Device            string

	geoInfo       *GeoInfo
	anonymousInfo *AnonymousInfo
}

// SetGeoInfo sets the geo information for the session.
func (s *SessionClientDeviceData) SetGeoInfo(geoInfo *GeoInfo) {
	s.geoInfo = geoInfo
}

// GeoInfo retrieves the geo information for the session.
func (s *SessionClientDeviceData) GeoInfo() *GeoInfo {
	return s.geoInfo
}

// SetAnonymousInfo sets the anonymous information for the session.
func (s *SessionClientDeviceData) SetAnonymousInfo(anonymousInfo *AnonymousInfo) {
	s.anonymousInfo = anonymousInfo
}

// AnonymousInfo retrieves the anonymous information for the session.
func (s *SessionClientDeviceData) AnonymousInfo() *AnonymousInfo {
	return s.anonymousInfo
}

// SessionID represents the identifier assigned to an authenticated session.
type SessionID string

// String returns the string representation of the SessionID.
func (s SessionID) String() string {
	return string(s)
}

// SessionToken encapsulates the tokens generated for an authenticated session.
type SessionToken struct {
	SessionID        SessionID
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
}

// SessionIssueParams captures the necessary information to mint a new session.
type SessionIssueParams struct {
	UserID ID
	SessionClientDeviceData
	// SignedInAt is when the login this session continues began, and lands in
	// sessions.created_at. A refresh replaces the row rather than updating it,
	// so without carrying this forward every rotation would reset the sign-in
	// time and the session list would claim a week-old login started minutes
	// ago. Zero means a fresh sign-in.
	SignedInAt time.Time
}

// ContextAuthenticatedSessionKey defines the request context key storing the authenticated session.
type ContextAuthenticatedSessionKey struct{}

// AuthenticatedSession contains the context extracted from a validated access token.
type AuthenticatedSession struct {
	SessionID SessionID
	UserID    ID
	IssuedAt  time.Time
	ExpiresAt time.Time
	SessionClientDeviceData
	RawToken string
}

// ValidateOptions says which of the two checks past the signature a caller may
// waive.
//
// They used to be one flag. isExpiredToken checked exp and the revocation cache
// together, and a single "skip expired validation" boolean turned both off --
// so any caller that wanted to read an expired token also stopped asking whether
// the session had been revoked. notification-service passes that flag on every
// websocket handshake, which meant a signed-out user, a user whose sessions were
// revoked by a password change, and a user an admin had just blocked all kept
// authenticating as long as they held the JWT.
type ValidateOptions struct {
	// AllowExpired accepts a token past exp. Refreshing needs it -- reading an
	// expired access token is the point of the endpoint -- and the websocket
	// handshake uses it so a connection is not refused in the seconds before the
	// client refreshes.
	AllowExpired bool

	// AllowRevoked accepts a session marked revoked, and is deliberately not
	// reachable from any cross-service contract.
	//
	// Only the refresh route sets it, and only because rotation revokes the
	// session it replaces: without this, presenting an already-rotated refresh
	// token would be turned away here and detectRefreshTokenReuse -- the thing
	// that notices a leaked token and ends every session of the user -- would
	// never run.
	AllowRevoked bool
}

// SessionHelper defines the capabilities required to issue and validate sessions.
type SessionHelper interface {
	Issue(context.Context, SessionIssueParams) (SessionToken, error)
	Validate(context.Context, string, ValidateOptions) (AuthenticatedSession, error)

	// HashRefreshToken derives the value stored for a refresh token. The helper
	// owns the token's format, so it owns the hashing too — and having one
	// function serve both the issuing and the verifying path is what keeps them
	// from drifting apart.
	HashRefreshToken(string) string
}

// Session represents a persisted user session stored in the sessions table.
type Session struct {
	UUID     SessionID
	ExpireAt *time.Time
	UserID   ID
	// RefreshTokenHash is the SHA-256 of the refresh token, never the token
	// itself. The raw value exists only in the response that issued it and in
	// the client holding it.
	RefreshTokenHash string
	RefreshExpireAt  *time.Time
	City             string
	CountryName      string
	*AnonymousInfo
	SessionClientDeviceData
	// CreatedAt is when the login began, carried across refreshes.
	CreatedAt time.Time
	// LastActivityAt is stamped every time the row is written, so it tracks the
	// last token refresh -- at most one access-token lifetime behind the user's
	// real last request. There is no per-request write: session validation never
	// touches this table, and adding a write to it would put a round trip on
	// every authenticated request to sharpen a timestamp nobody reads that
	// closely.
	LastActivityAt *time.Time
}

// SessionRepository defines the operations supported for persisted sessions.
type SessionRepository interface {
	Create(context.Context, *Session) error
	FindByUUID(context.Context, SessionID) (Session, error)
	FindByUUIDForUpdate(context.Context, SessionID) (Session, error)
	ListByUserID(context.Context, ID) ([]Session, error)
	DeleteByUUID(context.Context, SessionID) error
	DeleteByUserID(context.Context, ID) error

	// DeleteUnusableBefore removes sessions whose access and refresh windows have
	// both closed, returning how many went. Such a row can no longer authenticate
	// or refresh anything; it only makes ListSessions show the user devices they
	// signed out of months ago.
	DeleteUnusableBefore(context.Context, time.Time) (int64, error)

	WithTxFromContext(context.Context) SessionRepository
}

// SessionRevocationReason describes why a session was revoked.
type SessionRevocationReason uint8

// Revocation reasons are a cross-repository contract: admin-service casts
// revoked_sessions.reason to a backed PHP enum, so a value it does not know
// throws when the page hydrates the row. Add one here and there together, and
// ship admin-service first.
const (
	SessionRevocationReasonLogout SessionRevocationReason = iota + 1
	SessionRevocationReasonAdminKick
	SessionRevocationReasonPasswordChange
	SessionRevocationReasonUserRevoke
	SessionRevocationReasonRefresh
	SessionRevocationReasonTokenReuse
)

var sessionRevocationReasonToString = map[SessionRevocationReason]string{
	SessionRevocationReasonLogout:         "logout",
	SessionRevocationReasonAdminKick:      "admin_kick",
	SessionRevocationReasonPasswordChange: "password_change",
	SessionRevocationReasonUserRevoke:     "user_revoke",
	SessionRevocationReasonRefresh:        "refresh",
	SessionRevocationReasonTokenReuse:     "token_reuse",
}

// String returns the string representation of the revocation reason.
func (r SessionRevocationReason) String() string {
	if val, ok := sessionRevocationReasonToString[r]; ok {
		return val
	}
	return "unknown"
}

// Uint8 returns the uint8 representation for storage.
func (r SessionRevocationReason) Uint8() uint8 {
	return uint8(r)
}

// RevokedSession captures a revoked JWT session identifier.
type RevokedSession struct {
	UUID   SessionID
	UserID ID
	Reason SessionRevocationReason
	// RefreshTokenHash is the hash the session carried when it was revoked.
	// Refreshing deletes the session row, so this is the only thing left to
	// compare a replayed refresh token against. Empty for rows written before
	// the column existed.
	RefreshTokenHash string
	CreatedAt        time.Time
	ExpireAt         *time.Time
}

// RevokedSessionRepository handles persistence of revoked sessions.
type RevokedSessionRepository interface {
	Create(context.Context, *RevokedSession) error
	FindByUUID(context.Context, SessionID) (RevokedSession, error)

	// DeleteCreatedBefore removes revoked rows older than the cutoff, returning
	// how many went. The cutoff has to outlast the refresh token TTL: the hash
	// stored here is what reuse detection compares a replayed token against.
	DeleteCreatedBefore(context.Context, time.Time) (int64, error)

	WithTxFromContext(context.Context) RevokedSessionRepository
}

// AuthLogStatus denotes the result of an auth related event.
type AuthLogStatus uint8

// Like the revocation reasons above, these are a cross-repository contract:
// admin-service casts auth_logs.status to a backed PHP enum and throws on a
// value it does not know. Add one here and there together, admin-service first.
const (
	AuthLogStatusLoginSuccess AuthLogStatus = iota + 1
	AuthLogStatusLogout
	AuthLogStatusLogoutAll
	AuthLogStatusSessionRevoked
	AuthLogStatusSessionRefresh
	AuthLogStatusLoginFailed
)

// Uint8 converts the status to uint8 for storage.
func (s AuthLogStatus) Uint8() uint8 {
	return uint8(s)
}

// AuthLog represents an authentication audit record.
type AuthLog struct {
	ID          uint64
	UserID      ID
	City        string
	CountryName string
	*AnonymousInfo
	SessionClientDeviceData
	Status    AuthLogStatus
	CreatedAt time.Time
}

// NewAuthLog creates a new AuthLog
func NewAuthLog(session AuthenticatedSession, status AuthLogStatus) *AuthLog {
	return &AuthLog{
		UserID:                  session.UserID,
		SessionClientDeviceData: session.SessionClientDeviceData,
		Status:                  status,
	}
}

// AuthLogRepository persists authentication logs.
type AuthLogRepository interface {
	Create(context.Context, *AuthLog) error

	WithTxFromContext(context.Context) AuthLogRepository
}

// SessionRefreshParams encapsulates the fields required to refresh an existing session.
type SessionRefreshParams struct {
	AuthSession  AuthenticatedSession
	RefreshToken string
	SessionClientDeviceData
}

// SessionController exposes user session management use cases.
type SessionController interface {
	Issue(context.Context, *SessionIssueParams) (SessionToken, error)
	Logout(context.Context, AuthenticatedSession) error
	LogoutAll(context.Context, AuthenticatedSession) error
	ListSessions(context.Context, ID) ([]Session, error)
	RevokeSession(context.Context, AuthenticatedSession, SessionID) error
	RevokeSessionByAdmin(context.Context, SessionID) error
	RefreshSession(context.Context, SessionRefreshParams) (SessionToken, error)

	// RevokeAllOnBlock revokes every session the user holds, on the caller's
	// transaction, so that blocking an account and ending its sessions commit
	// together. Same contract as RevokeAllOnPasswordChange below.
	RevokeAllOnBlock(context.Context, ID) *appErrors.ErrorResponse

	// RevokeAllOnPasswordChange revokes every session of the user except the one
	// passed in, which is the session performing the password change.
	//
	// An empty SessionID spares nothing, which is what password recovery needs:
	// the caller there is unauthenticated and has no session of their own.
	//
	// Unlike every other method here it does not own a transaction: it runs on the
	// caller's, so the revocation and the credential update it accompanies commit
	// together or not at all. The caller must have both an open transaction and a
	// cache clean map (cache.NewCleanMap) on the context.
	RevokeAllOnPasswordChange(context.Context, AuthenticatedSession) error
}
