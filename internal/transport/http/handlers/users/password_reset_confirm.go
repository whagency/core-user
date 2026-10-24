package users

import (
	"net/http"

	"user-service/internal/domain"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
)

// PasswordResetConfirmHandler finalizes password reset challenges.
type PasswordResetConfirmHandler struct {
	ctrl domain.PasswordRecoveryController
}

// NewPasswordResetConfirmHandler builds a new PasswordResetConfirmHandler instance.
func NewPasswordResetConfirmHandler(ctrl domain.PasswordRecoveryController) *PasswordResetConfirmHandler {
	return &PasswordResetConfirmHandler{ctrl: ctrl}
}

type passwordResetConfirmRequest struct {
	TokenUUID   string `json:"tokenUUID" validate:"required,uuid4" example:"0ea1fb64-7c54-43a6-bff9-f0ae1c0b19dc"`
	Code        string `json:"code" validate:"required,not_blank,numeric_code,min=4,max=12" example:"532110"`
	NewPassword string `json:"newPassword" validate:"required,not_blank,password" example:"password"`
}

// Handle verifies the OTP and rotates the password.
//
//	@Summary        Confirm password reset
//	@Description    Verifies the password reset OTP and rotates the user's credentials. Any active sessions are revoked.
//	@Tags           users
//	@Accept         json
//	@Produce        json
//	@Param          request body passwordResetConfirmRequest true "Password reset payload"
//	@Success        200 {object} commonHTTP.Response "Password updated successfully."
//	@Failure        400 {object} commonHTTP.Response "Malformed JSON payload."
//	@Failure        401 {object} commonHTTP.Response "Invalid or expired verification code."
//	@Failure        404 {object} commonHTTP.Response "Password reset challenge not found."
//	@Failure        409 {object} commonHTTP.Response "Concurrency conflict while validating the challenge."
//	@Failure        422 {object} commonHTTP.Response "Validation errors in the request body."
//	@Failure        429 {object} commonHTTP.Response "Maximum verification attempts exceeded."
//	@Failure        500 {object} commonHTTP.Response "Failed to reset the password due to internal errors."
//	@Router         /api/v1/users/password/reset/confirm [post]
func (h PasswordResetConfirmHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	var req passwordResetConfirmRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[PasswordResetConfirmHandler:Handle]") {
		return
	}

	if err := h.ctrl.Confirm(ctx, req.toDomain()); commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, nil))
}

// toDomain converts passwordResetConfirmRequest to domain.PasswordResetConfirmParams.
func (r passwordResetConfirmRequest) toDomain() domain.PasswordResetConfirmParams {
	return domain.PasswordResetConfirmParams{
		TokenUUID:   r.TokenUUID,
		Code:        r.Code,
		NewPassword: r.NewPassword,
	}
}
