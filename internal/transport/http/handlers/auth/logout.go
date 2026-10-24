package auth

import (
	"net/http"

	"user-service/internal/domain"
	httpHandlers "user-service/internal/transport/http/handlers"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
)

// LogoutHandler handles session termination for the authenticated user.
type LogoutHandler struct {
	ctrl domain.SessionController
}

// NewLogoutHandler builds a new LogoutHandler instance.
func NewLogoutHandler(ctrl domain.SessionController) *LogoutHandler {
	return &LogoutHandler{ctrl: ctrl}
}

type logoutResponse struct {
	SessionID string `json:"sessionId" example:"06fd3021-b659-44e2-b86c-d45ec3fc75ac"`
}

// Handle revokes the current access session.
//
//	@Summary        Logout current session
//	@Description    Invalidates the access token and removes the refresh token associated with the caller's session.
//	@Tags           auth
//	@Security       Authorization
//	@Produce        json
//	@Success        200 {object} commonHTTP.Response{data=logoutResponse} "Session successfully revoked."
//	@Failure        401 {object} commonHTTP.Response "Missing or invalid access token."
//	@Failure        500 {object} commonHTTP.Response "Failed to revoke the session due to internal issues."
//	@Router         /api/v1/auth/logout [post]
func (h LogoutHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	session, ok := httpHandlers.RequireAuthenticatedSession(c, "[LogoutHandler:Handle]")
	if !ok {
		return
	}

	err := h.ctrl.Logout(ctx, session)
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, logoutResponse{SessionID: session.SessionID.String()}))
}
