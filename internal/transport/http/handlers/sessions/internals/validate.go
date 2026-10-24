package internals

import (
	"errors"
	"fmt"
	"net/http"

	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"
	"user-service/internal/infrastructure/security/sessions"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	appErrors "github.com/whagency/core-common/errorsx"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
	"github.com/whagency/core-common/logger"
)

// ValidateSessionHandler validates a session token for internal consumers and returns user context.
type ValidateSessionHandler struct {
	sessionHelper domain.SessionHelper
	userCtrl      domain.UserController
}

// NewValidateSessionHandler constructs a ValidateSessionHandler instance.
func NewValidateSessionHandler(sessionHelper domain.SessionHelper, userCtrl domain.UserController) *ValidateSessionHandler {
	return &ValidateSessionHandler{
		sessionHelper: sessionHelper,
		userCtrl:      userCtrl,
	}
}

type validateSessionRequest struct {
	Token string `json:"token" validate:"required,not_blank" example:"alsbfiu4aiwfbibouywo3fasy"`
	// IsExpiredValidationSkip accepts a token past its expiry. It does not accept
	// a revoked session: a signed-out, password-rotated or admin-blocked session
	// is refused whatever this is set to.
	IsExpiredValidationSkip bool `json:"isExpiredValidationSkip" example:"false"`
}

type validateSessionResponse struct {
	SessionID string              `json:"sessionId" example:"06fd3021-b659-44e2-b86c-d45ec3fc75ac"`
	User      validateSessionUser `json:"user"`
}

type validateSessionUser struct {
	ID                uint64  `json:"id" example:"123"`
	VerificationLevel string  `json:"verificationLevel" example:"basic"`
	Country           string  `json:"country" example:"Ukraine"`
	Timezone          *string `json:"timezone,omitempty" example:"Europe/Kyiv"`
	Locale            *string `json:"locale,omitempty" example:"en_US"`
	Status            string  `json:"status" example:"active"`
}

// Handle validates the provided session token and returns session and user details.
//
//	@Summary        Validate a user session token
//	@Description    Validates a session token and returns basic user information for internal services.
//	@Tags           internal
//	@Accept         json
//	@Produce        json
//	@Param          request body validateSessionRequest true "Session token payload"
//	@Success        200 {object} commonHTTP.Response{data=validateSessionResponse} "Session is valid."
//	@Failure        400 {object} commonHTTP.Response "Missing or malformed request payload."
//	@Failure        401 {object} commonHTTP.Response "Session token is invalid or expired."
//	@Failure        404 {object} commonHTTP.Response "User not found."
//	@Failure        500 {object} commonHTTP.Response "Failed to validate the session due to internal errors."
//	@Router         /api/v1/internal/sessions/validate [post]
func (h ValidateSessionHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	var req validateSessionRequest
	if ok := commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[ValidateSessionHandler:Handle]"); !ok {
		return
	}

	// Waives expiry only. A revoked session is refused however the caller asks --
	// see domain.ValidateOptions.
	session, err := h.sessionHelper.Validate(ctx, req.Token, domain.ValidateOptions{
		AllowExpired: req.IsExpiredValidationSkip,
	})
	if err != nil {
		var er *appErrors.ErrorResponse
		if errors.Is(err, sessions.ErrExpired) || errors.Is(err, sessions.ErrRevoked) {
			er = svcErrors.New(
				appErrors.UserSessionExpiredError,
				appErrors.WithCause(fmt.Errorf("[ValidateSessionHandler:Handle]%w", err)),
			)
		} else {
			er = svcErrors.New(
				appErrors.UserSessionTokenInvalidError,
				appErrors.WithCause(fmt.Errorf("[ValidateSessionHandler:Handle]%w", err)),
			)
			logger.LogCtx(ctx).Errorf("[ValidateSessionHandler:Handle]%s", err)
		}

		c.AbortWithStatusJSON(er.HTTPStatus, commonHTTP.EncodeErrorResponse(ctx, er))
		return
	}

	profile, err := h.userCtrl.GetProfile(ctx, session.UserID)
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, encodeValidateSessionResponse(session, profile)))
}

// encodeValidateSessionResponse encodes the validated session and user profile into a response format.
func encodeValidateSessionResponse(session domain.AuthenticatedSession, profile domain.UserProfile) validateSessionResponse {
	return validateSessionResponse{
		SessionID: session.SessionID.String(),
		User: validateSessionUser{
			ID:                profile.UserID.Uint64(),
			VerificationLevel: profile.VerificationLevel.String(),
			Country:           profile.ProfileDetails.Country,
			Timezone:          profile.ProfileDetails.Timezone,
			Locale:            profile.ProfileDetails.Locale,
			Status:            profile.Status.String(),
		},
	}
}
