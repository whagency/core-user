package protected

import (
	"net/http"
	"strings"

	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"
	httpHandlers "user-service/internal/transport/http/handlers"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	appErrors "github.com/whagency/core-common/errorsx"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
	commonTools "github.com/whagency/core-common/tools"
)

// TwoFactorConfirmHandler verifies the two-factor challenge code to enable or disable a method.
type TwoFactorConfirmHandler struct {
	ctrl domain.TwoFactorController
}

// NewTwoFactorConfirmHandler builds a new TwoFactorConfirmHandler instance.
func NewTwoFactorConfirmHandler(ctrl domain.TwoFactorController) *TwoFactorConfirmHandler {
	return &TwoFactorConfirmHandler{ctrl: ctrl}
}

type twoFactorConfirmRequest struct {
	TokenUUID string `json:"tokenUUID" validate:"required,uuid4" example:"06fd3021-b659-44e2-b86c-d45ec3fc75ac"`
	Code      string `json:"code" validate:"required,not_blank,numeric_code,min=4,max=12" example:"457090"`
	Action    string `json:"action" validate:"omitempty" enums:"activate,deactivate" example:"activate"`
}

// _twoFactorConfirmAllowedActions defines the explicit actions accepted by the confirmation endpoint.
var _twoFactorConfirmAllowedActions = []domain.TwoFactorAction{
	domain.TwoFactorActionActivate,
	domain.TwoFactorActionDeactivate,
}

// Handle validates the request payload and delegates the two-factor confirmation command.
//
//	@Summary        Confirm two-factor authentication
//	@Description    Confirms a two-factor authentication challenge using the provided code.
//	@Tags           2FA
//	@Security       Authorization
//	@Accept         json
//	@Produce        json
//	@Param          request body twoFactorConfirmRequest true "Two-factor confirmation payload"
//	@Success        200 {object} commonHTTP.Response "Two-factor settings updated."
//	@Failure        400 {object} commonHTTP.Response "Malformed JSON payload."
//	@Failure        401 {object} commonHTTP.Response "Invalid access token or challenge code."
//	@Failure        404 {object} commonHTTP.Response "User or challenge not found."
//	@Failure        409 {object} commonHTTP.Response "Concurrency conflict while confirming the challenge."
//	@Failure        422 {object} commonHTTP.Response "Validation errors in the request body."
//	@Failure        429 {object} commonHTTP.Response "Maximum verification attempts exceeded."
//	@Failure        500 {object} commonHTTP.Response "Failed to update the two-factor settings due to internal errors."
//	@Router         /api/v1/2fa/confirm [post]
func (h TwoFactorConfirmHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	session, ok := httpHandlers.RequireAuthenticatedSession(c, "[TwoFactorConfirmHandler:Handle]")
	if !ok {
		return
	}

	var req twoFactorConfirmRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[TwoFactorConfirmHandler:Handle]") {
		return
	}

	action, errResponse := decodeTwoFactorConfirmAction("[TwoFactorConfirmHandler:Handle]", "action", req.Action)
	if errResponse != nil {
		c.AbortWithStatusJSON(errResponse.HTTPStatus, commonHTTP.EncodeErrorResponse(ctx, errResponse))
		return
	}

	if err := h.ctrl.Confirm(ctx, domain.TwoFactorConfirmParams{
		UserID:    session.UserID,
		TokenUUID: req.TokenUUID,
		Code:      req.Code,
		Action:    action,
	}); commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, nil))
}

// decodeTwoFactorConfirmAction validates and converts the confirm action.
func decodeTwoFactorConfirmAction(scope, field, value string) (domain.TwoFactorAction, *appErrors.ErrorResponse) {
	if strings.TrimSpace(value) == "" {
		return domain.TwoFactorActionActivate, nil
	}

	action, err := domain.NewTwoFactorActionFromString(value)
	if err == nil {
		return action, nil
	}

	return 0, svcErrors.NewOneOfValidationError(scope, field, value, commonTools.StringValues(_twoFactorConfirmAllowedActions))
}
