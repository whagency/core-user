package handlers

import (
	"errors"
	"fmt"

	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"
	"user-service/internal/transport/http/middleware"

	"github.com/gin-gonic/gin"
	appErrors "github.com/whagency/core-common/errorsx"
	commonHTTP "github.com/whagency/core-common/http"
	"github.com/whagency/core-common/logger"
)

// RequireAuthenticatedSession extracts the authenticated session from middleware state.
// If the session is missing, a standardized 500 error response is produced and the handler must stop.
func RequireAuthenticatedSession(c *gin.Context, logPrefix string) (domain.AuthenticatedSession, bool) {
	ctx := c.Request.Context()

	session, ok := middleware.AuthenticatedSessionFromContext(c)
	if ok {
		return session, true
	}

	causeMessage := "[err: missing authenticated session context]"
	if logPrefix != "" {
		causeMessage = fmt.Sprintf("%s%s", logPrefix, causeMessage)
	}

	er := svcErrors.New(
		appErrors.InternalServerError,
		appErrors.WithCause(errors.New(causeMessage)),
	)
	logger.LogCtx(ctx).Error(er.Cause)
	c.AbortWithStatusJSON(er.HTTPStatus, commonHTTP.EncodeErrorResponse(ctx, er))
	return domain.AuthenticatedSession{}, false
}
