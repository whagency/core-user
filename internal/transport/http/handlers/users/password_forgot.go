package users

import (
	"net/http"
	"time"

	"user-service/internal/domain"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
)

// PasswordForgotHandler handles password recovery requests.
type PasswordForgotHandler struct {
	ctrl domain.PasswordRecoveryController
}

// NewPasswordForgotHandler builds a new PasswordForgotHandler instance.
func NewPasswordForgotHandler(ctrl domain.PasswordRecoveryController) *PasswordForgotHandler {
	return &PasswordForgotHandler{ctrl: ctrl}
}

type passwordForgotRequest struct {
	Identifier string `json:"identifier" validate:"required,not_blank,min=5,max=255,identifier" example:"test.email@gmail.com"`
	Recaptcha  string `json:"recaptcha" validate:"required,not_blank" example:"recaptcha-token-value"`
}

type passwordForgotResponse struct {
	ContactMasked string `json:"contactMasked" example:"te***@gmail.com"`
	TokenUUID     string `json:"tokenUUID" example:"0ea1fb64-7c54-43a6-bff9-f0ae1c0b19dc"`
	ExpiresAt     string `json:"expiresAt" example:"2026-03-02T06:31:43Z"`
}

// decode converts passwordForgotRequest to domain.PasswordResetRequestParams.
func (r passwordForgotRequest) decode() domain.PasswordResetRequestParams {
	return domain.PasswordResetRequestParams{
		Identifier: r.Identifier,
		Recaptcha:  r.Recaptcha,
	}
}

// Handle issues an OTP for password recovery.
//
//	@Summary        Forgot password
//	@Description    Initiates the password recovery flow and sends an OTP to the user's verified primary contact.
//	@Tags           users
//	@Accept         json
//	@Produce        json
//	@Param          request body passwordForgotRequest true "Password recovery payload"
//	@Success        202 {object} commonHTTP.Response{data=passwordForgotResponse} "Recovery challenge issued."
//	@Failure        400 {object} commonHTTP.Response "Malformed JSON payload."
//	@Failure        401 {object} commonHTTP.Response "Unknown account or invalid credentials."
//	@Failure        403 {object} commonHTTP.Response "Account blocked or primary contact unverified."
//	@Failure        409 {object} commonHTTP.Response "Pending recovery challenge already exists."
//	@Failure        422 {object} commonHTTP.Response "Validation errors in the request body."
//	@Failure        500 {object} commonHTTP.Response "Failed to create the recovery challenge due to internal errors."
//	@Router         /api/v1/users/password/forgot [post]
func (h PasswordForgotHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	var req passwordForgotRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[PasswordForgotHandler:Handle]") {
		return
	}

	result, err := h.ctrl.Request(ctx, req.decode())
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusAccepted, commonHTTP.EncodeSuccessResponse(ctx, encodePasswordForgotResponse(result)))
}

// encodePasswordForgotResponse encodes domain.PasswordResetRequestResult to passwordForgotResponse.
func encodePasswordForgotResponse(r domain.PasswordResetRequestResult) passwordForgotResponse {
	return passwordForgotResponse{
		ContactMasked: r.ContactMethod.GetMaskedContactValue(),
		TokenUUID:     r.TokenUUID,
		ExpiresAt:     r.ExpiresAt.Format(time.RFC3339),
	}
}
