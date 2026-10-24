package protected

import (
	"net/http"

	"user-service/internal/domain"
	svcHTTP "user-service/internal/transport/http"
	httpHandlers "user-service/internal/transport/http/handlers"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
)

// PasswordChangeHandler handles password rotation requests for authenticated users.
type PasswordChangeHandler struct {
	ctrl domain.UserController
}

// NewPasswordChangeHandler builds a new PasswordChangeHandler instance.
func NewPasswordChangeHandler(c domain.UserController) *PasswordChangeHandler {
	return &PasswordChangeHandler{ctrl: c}
}

type passwordChangeRequest struct {
	CurrentPassword string `json:"currentPassword" validate:"required,not_blank" example:"password"`
	NewPassword     string `json:"newPassword" validate:"required,not_blank,password" example:"new_password"`
}

// toDomain converts passwordChangeRequest to domain.PasswordChangeParams.
func (r passwordChangeRequest) toDomain(session domain.AuthenticatedSession, deviceData domain.SessionClientDeviceData) domain.PasswordChangeParams {
	return domain.PasswordChangeParams{
		UserID:                  session.UserID,
		SessionID:               session.SessionID,
		CurrentPassword:         r.CurrentPassword,
		NewPassword:             r.NewPassword,
		SessionClientDeviceData: deviceData,
	}
}

// Handle validates the request payload and delegates the password rotation command.
//
//	@Summary        Change password
//	@Description    Rotates the authenticated user's password and revokes every other session of the user.
//	@Description    The session making the request stays valid, so the caller keeps its access and refresh tokens.
//	@Description    All other devices are signed out and their refresh tokens stop working immediately.
//	@Tags           users
//	@Security       Authorization
//	@Accept         json
//	@Produce        json
//	@Param          request body passwordChangeRequest true "Password change payload"
//	@Success        200 {object} commonHTTP.Response "Password updated."
//	@Failure        400 {object} commonHTTP.Response "Malformed JSON payload."
//	@Failure        401 {object} commonHTTP.Response "Invalid access token or incorrect current password."
//	@Failure        403 {object} commonHTTP.Response "Password reuse policy violation."
//	@Failure        404 {object} commonHTTP.Response "User credentials not found."
//	@Failure        422 {object} commonHTTP.Response "Validation errors in the request body."
//	@Failure        500 {object} commonHTTP.Response "Failed to change the password due to internal errors."
//	@Router         /api/v1/users/password-change [post]
func (h PasswordChangeHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	session, ok := httpHandlers.RequireAuthenticatedSession(c, "[PasswordChangeHandler:Handle]")
	if !ok {
		return
	}

	var req passwordChangeRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[PasswordChangeHandler:Handle]") {
		return
	}

	if err := h.ctrl.ChangePassword(ctx, req.toDomain(session, svcHTTP.NewSessionClientDeviceData(c))); commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, nil))
}
