package middleware

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"
	"user-service/internal/infrastructure/security/sessions"

	"github.com/gin-gonic/gin"
	appErrors "github.com/whagency/core-common/errorsx"
	commonHTTP "github.com/whagency/core-common/http"
)

// _authenticatedSessionContextKey Store in both request context and Gin context for convenience.
const _authenticatedSessionContextKey = "authenticatedSession"

type ValidateSessionOptions struct {
	// AllowExpired treats a token past exp as readable. Revocation is still
	// checked -- there is deliberately no option here to waive that. The one
	// route that needs to is served by ValidateUserSessionForRefresh.
	AllowExpired bool
}

// ValidateUserSession ensures requests carry a valid user access token.
// It passes the raw Authorization header to SessionHelper.Validate — which accepts either
// a raw JWT or "Bearer <jwt>" — so the middleware doesn't need to parse headers itself.
func ValidateUserSession(session domain.SessionHelper, opts ValidateSessionOptions) gin.HandlerFunc {
	return validateUserSession(session, domain.ValidateOptions{AllowExpired: opts.AllowExpired})
}

// ValidateUserSessionForRefresh is the refresh endpoint's own guard, and the only
// caller anywhere that accepts a revoked session.
//
// Rotation revokes the session it replaces, so a replayed refresh token arrives
// with an access token for a session already marked revoked. Turning it away here
// would look like ordinary hygiene and would quietly disable reuse detection:
// SessionCtrl.RefreshSession is where a replay is recognized and answered by
// ending every session the user has. It is a named function rather than a boolean
// so that using it is a decision somebody had to write down.
func ValidateUserSessionForRefresh(session domain.SessionHelper) gin.HandlerFunc {
	return validateUserSession(session, domain.ValidateOptions{AllowExpired: true, AllowRevoked: true})
}

func validateUserSession(session domain.SessionHelper, opts domain.ValidateOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		authToken := strings.TrimSpace(c.GetHeader("Authorization"))
		if authToken == "" {
			er := svcErrors.New(
				appErrors.UserSessionTokenInvalidError,
				appErrors.WithCause(fmt.Errorf("[middleware:ValidateUserSession][err: missing authorization header]")),
			)
			c.AbortWithStatusJSON(er.HTTPStatus, commonHTTP.EncodeErrorResponse(ctx, er))
			return
		}

		authSession, err := session.Validate(ctx, authToken, opts)
		if err != nil {
			var er *appErrors.ErrorResponse
			if errors.Is(err, sessions.ErrExpired) || errors.Is(err, sessions.ErrRevoked) {
				er = svcErrors.New(
					appErrors.UserSessionExpiredError,
					appErrors.WithCause(fmt.Errorf("[middleware:ValidateUserSession]%w", err)),
				)
			} else {
				er = svcErrors.New(
					appErrors.UserSessionTokenInvalidError,
					appErrors.WithCause(fmt.Errorf("[middleware:ValidateUserSession]%w", err)),
				)
			}

			c.AbortWithStatusJSON(er.HTTPStatus, commonHTTP.EncodeErrorResponse(ctx, er))
			return
		}

		// Attach to request context and Gin context
		ctxWithSession := context.WithValue(ctx, domain.ContextAuthenticatedSessionKey{}, authSession)
		c.Request = c.Request.WithContext(ctxWithSession)
		c.Set(_authenticatedSessionContextKey, authSession)

		c.Next()
	}
}

// AuthenticatedSessionFromContext retrieves the authenticated session from gin context
// or from the request context, whichever is available.
func AuthenticatedSessionFromContext(c *gin.Context) (domain.AuthenticatedSession, bool) {
	if raw, ok := c.Get(_authenticatedSessionContextKey); ok {
		if s, isValid := raw.(domain.AuthenticatedSession); isValid {
			return s, true
		}
	}
	if raw := c.Request.Context().Value(domain.ContextAuthenticatedSessionKey{}); raw != nil {
		if s, ok := raw.(domain.AuthenticatedSession); ok {
			return s, true
		}
	}
	return domain.AuthenticatedSession{}, false
}
