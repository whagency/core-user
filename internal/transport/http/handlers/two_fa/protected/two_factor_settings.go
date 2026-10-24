package protected

import (
	"net/http"
	"time"

	"user-service/internal/domain"
	httpHandlers "user-service/internal/transport/http/handlers"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
)

// TwoFactorSettingsHandler exposes the current two-factor configuration for the authenticated user.
type TwoFactorSettingsHandler struct {
	ctrl domain.TwoFactorController
}

// NewTwoFactorSettingsHandler builds a new TwoFactorSettingsHandler instance.
func NewTwoFactorSettingsHandler(ctrl domain.TwoFactorController) *TwoFactorSettingsHandler {
	return &TwoFactorSettingsHandler{ctrl: ctrl}
}

type twoFactorSettingsResponse struct {
	ContactMasked *string `json:"contactMasked,omitempty" example:"te***@gmail.com"`
	Method        string  `json:"method" example:"email"`
	CreatedAt     string  `json:"createdAt" example:"2026-03-02T06:31:43Z"`
}

// Handle handles the HTTP request.
//
//	@Summary        Get two-factor authentication settings
//	@Description    Retrieves the current two-factor authentication settings for the authenticated user.
//	@Tags           2FA
//	@Security       Authorization
//	@Produce        json
//	@Success        200 {object} commonHTTP.Response{data=twoFactorSettingsResponse} "Two-factor settings retrieved."
//	@Failure        401 {object} commonHTTP.Response "Missing or invalid access token."
//	@Failure        404 {object} commonHTTP.Response "Two-factor settings not found."
//	@Failure        500 {object} commonHTTP.Response "Failed to load settings due to internal errors."
//	@Router         /api/v1/2fa/settings [get]
func (h TwoFactorSettingsHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	session, ok := httpHandlers.RequireAuthenticatedSession(c, "[TwoFactorSettingsHandler:Handle]")
	if !ok {
		return
	}

	result, err := h.ctrl.GetSettings(ctx, session.UserID)
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, encodeTwoFactorSettingsResponse(result)))
}

// encodeTwoFactorSettingsResponse encodes the domain response to the transport response.
func encodeTwoFactorSettingsResponse(in domain.TwoFactorGetSettingsResult) twoFactorSettingsResponse {
	settings := twoFactorSettingsResponse{
		Method:    in.Method.String(),
		CreatedAt: in.CreatedAt.Format(time.RFC3339),
	}

	if in.Contact != nil {
		contactMasked := in.Contact.GetMaskedContactValue()
		settings.ContactMasked = &contactMasked
	}

	return settings
}
