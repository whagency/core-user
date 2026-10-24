package protected

import (
	"net/http"
	"slices"

	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"
	httpHandlers "user-service/internal/transport/http/handlers"
	twoFaHandlers "user-service/internal/transport/http/handlers/two_fa"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	appErrors "github.com/whagency/core-common/errorsx"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
	commonTools "github.com/whagency/core-common/tools"
)

// TwoFactorActivateHandler issues challenges for enabling two-factor authentication.
type TwoFactorActivateHandler struct {
	ctrl domain.TwoFactorController
}

// NewTwoFactorActivateHandler builds a new TwoFactorActivateHandler instance.
func NewTwoFactorActivateHandler(ctrl domain.TwoFactorController) *TwoFactorActivateHandler {
	return &TwoFactorActivateHandler{ctrl: ctrl}
}

type twoFactorActivateRequest struct {
	Method string `json:"method" validate:"required,not_blank" enums:"google,email" example:"email"`
}

// _twoFactorActivateAllowedMethods defines the two-factor methods accepted by the activation endpoint.
var _twoFactorActivateAllowedMethods = []domain.TwoFactorMethod{
	domain.TwoFactorMethodGoogle,
	domain.TwoFactorMethodEmail,
}

// Handle validates the request payload and delegates the two-factor activation challenge command.
//
//	@Summary        Activate two-factor authentication
//	@Description    Issues a challenge to activate two-factor authentication using the specified method.
//	@Tags           2FA
//	@Security       Authorization
//	@Accept         json
//	@Produce        json
//	@Param          request body twoFactorActivateRequest true "Two-factor activation payload"
//	@Success        202 {object} commonHTTP.Response{data=twoFaHandlers.TwoFactorChallengeResponse} "Challenge issued."
//	@Failure        400 {object} commonHTTP.Response "Malformed JSON payload or unsupported method."
//	@Failure        401 {object} commonHTTP.Response "Missing or invalid access token."
//	@Failure        404 {object} commonHTTP.Response "User or contact method not found."
//	@Failure        409 {object} commonHTTP.Response "Two-factor authentication already enabled."
//	@Failure        422 {object} commonHTTP.Response "Validation errors in the request body."
//	@Failure        500 {object} commonHTTP.Response "Failed to issue the activation challenge due to internal errors."
//	@Router         /api/v1/2fa/activate [post]
func (h TwoFactorActivateHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	session, ok := httpHandlers.RequireAuthenticatedSession(c, "[TwoFactorActivateHandler:Handle]")
	if !ok {
		return
	}

	var req twoFactorActivateRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[TwoFactorActivateHandler:Handle]") {
		return
	}

	method, errResponse := decodeTwoFactorActivateMethod("[TwoFactorActivateHandler:Handle]", "method", req.Method)
	if errResponse != nil {
		c.AbortWithStatusJSON(errResponse.HTTPStatus, commonHTTP.EncodeErrorResponse(ctx, errResponse))
		return
	}

	result, err := h.ctrl.Activate(ctx, domain.TwoFactorActivateParams{
		UserID: session.UserID,
		Method: method,
	})
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusAccepted, commonHTTP.EncodeSuccessResponse(ctx, twoFaHandlers.EncodeTwoFactorChallengeResponse(result)))
}

// decodeTwoFactorActivateMethod validates the allowed activation methods for HTTP transport.
func decodeTwoFactorActivateMethod(scope, field, value string) (domain.TwoFactorMethod, *appErrors.ErrorResponse) {
	method, err := domain.NewTwoFactorMethodFromString(value)
	if err == nil && slices.Contains(_twoFactorActivateAllowedMethods, method) {
		return method, nil
	}

	return 0, svcErrors.NewOneOfValidationError(scope, field, value, commonTools.StringValues(_twoFactorActivateAllowedMethods))
}
