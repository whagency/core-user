package protected

import (
	"net/http"

	"user-service/internal/domain"
	httpHandlers "user-service/internal/transport/http/handlers"
	twoFaHandlers "user-service/internal/transport/http/handlers/two_fa"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
)

// TwoFactorDeactivateHandler issues challenges for disabling two-factor authentication.
type TwoFactorDeactivateHandler struct {
	ctrl domain.TwoFactorController
}

// NewTwoFactorDeactivateHandler builds a new TwoFactorDeactivateHandler instance.
func NewTwoFactorDeactivateHandler(ctrl domain.TwoFactorController) *TwoFactorDeactivateHandler {
	return &TwoFactorDeactivateHandler{ctrl: ctrl}
}

// Handle handles the HTTP request.
//
//	@Summary        Deactivate two-factor authentication
//	@Description    Initiates the flow to disable two-factor authentication for the authenticated user.
//	@Tags           2FA
//	@Security       Authorization
//	@Produce        json
//	@Success        202 {object} commonHTTP.Response{data=twoFaHandlers.TwoFactorChallengeResponse} "Challenge issued."
//	@Failure        401 {object} commonHTTP.Response "Missing or invalid access token."
//	@Failure        404 {object} commonHTTP.Response "Two-factor settings not found."
//	@Failure        500 {object} commonHTTP.Response "Failed to issue the deactivation challenge due to internal errors."
//	@Router         /api/v1/2fa/deactivate [post]
func (h TwoFactorDeactivateHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	session, ok := httpHandlers.RequireAuthenticatedSession(c, "[TwoFactorDeactivateHandler:Handle]")
	if !ok {
		return
	}

	result, err := h.ctrl.Deactivate(ctx, domain.TwoFactorDeactivateParams{
		UserID: session.UserID,
	})
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusAccepted, commonHTTP.EncodeSuccessResponse(ctx, twoFaHandlers.EncodeTwoFactorChallengeResponse(result)))
}
