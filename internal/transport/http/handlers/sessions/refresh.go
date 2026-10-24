package sessions

import (
	"net/http"
	"time"

	"user-service/internal/domain"
	svcHTTP "user-service/internal/transport/http"
	httpHandlers "user-service/internal/transport/http/handlers"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
)

// RefreshSessionHandler handles session refresh requests.
type RefreshSessionHandler struct {
	ctrl domain.SessionController
}

// NewRefreshSessionHandler builds a new RefreshSessionHandler instance.
func NewRefreshSessionHandler(ctrl domain.SessionController) *RefreshSessionHandler {
	return &RefreshSessionHandler{ctrl: ctrl}
}

type refreshSessionRequest struct {
	RefreshToken string `json:"refreshToken" validate:"required,not_blank" example:"jahsbduaywefuabvkufviuawye"`
}

type refreshSessionResponse struct {
	Session SessionResponse `json:"session"`
}

// Handle processes a refresh token request and returns renewed session tokens.
//
//	@Summary        Refresh session tokens
//	@Description    Issues new access and refresh tokens for a valid session when presented with a valid refresh token.
//	@Tags           auth
//	@Accept         json
//	@Produce        json
//	@Param          request body refreshSessionRequest true "Session refresh payload"
//	@Success        200 {object} commonHTTP.Response{data=refreshSessionResponse} "Session refreshed."
//	@Failure        400 {object} commonHTTP.Response "Missing session identifier or malformed payload."
//	@Failure        401 {object} commonHTTP.Response "Invalid or expired refresh token."
//	@Failure        404 {object} commonHTTP.Response "Session not found."
//	@Failure        422 {object} commonHTTP.Response "Validation errors in the request body."
//	@Failure        500 {object} commonHTTP.Response "Failed to refresh the session due to internal errors."
//	@Router         /api/v1/auth/sessions/refresh [post]
func (h RefreshSessionHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	session, ok := httpHandlers.RequireAuthenticatedSession(c, "[RefreshSessionHandler:Handle]")
	if !ok {
		return
	}

	var req refreshSessionRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[RefreshSessionHandler:Handle]") {
		return
	}

	newSession, err := h.ctrl.RefreshSession(ctx, domain.SessionRefreshParams{
		AuthSession:             session,
		RefreshToken:            req.RefreshToken,
		SessionClientDeviceData: svcHTTP.NewSessionClientDeviceData(c),
	})
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, refreshSessionResponse{
		Session: SessionResponse{
			SessionID:           newSession.SessionID.String(),
			AccessToken:         newSession.AccessToken,
			AccessTokenExpires:  newSession.AccessExpiresAt.Format(time.RFC3339),
			RefreshToken:        newSession.RefreshToken,
			RefreshTokenExpires: newSession.RefreshExpiresAt.Format(time.RFC3339),
		},
	}))
}
