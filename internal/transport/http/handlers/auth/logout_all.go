package auth

import (
	"net/http"

	"user-service/internal/domain"
	httpHandlers "user-service/internal/transport/http/handlers"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
)

// LogoutAllHandler terminates every active session for the authenticated user.
type LogoutAllHandler struct {
	ctrl domain.SessionController
}

// NewLogoutAllHandler builds a new LogoutAllHandler instance.
func NewLogoutAllHandler(ctrl domain.SessionController) *LogoutAllHandler {
	return &LogoutAllHandler{ctrl: ctrl}
}

// Handle revokes all sessions associated with the user.
//
//	@Summary        Logout from all sessions
//	@Description    Revokes all sessions for the authenticated user, invalidating every refresh token on record.
//	@Tags           auth
//	@Security       Authorization
//	@Produce        json
//	@Success        200 {object} commonHTTP.Response{} "All sessions revoked."
//	@Failure        401 {object} commonHTTP.Response "Missing or invalid access token."
//	@Failure        500 {object} commonHTTP.Response "Unable to revoke sessions due to internal issues."
//	@Router         /api/v1/auth/logout-all [post]
func (h LogoutAllHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	session, ok := httpHandlers.RequireAuthenticatedSession(c, "[LogoutAllHandler:Handle]")
	if !ok {
		return
	}

	err := h.ctrl.LogoutAll(ctx, session)
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, nil))
}
