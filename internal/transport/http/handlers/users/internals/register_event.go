package internals

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	appErrors "github.com/whagency/core-common/errorsx"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
)

// RegisterEventHandler triggers the new user registration event.
type RegisterEventHandler struct {
	ctrl domain.UserEventController
}

// NewRegisterEventHandler builds a new RegisterEventHandler instance.
func NewRegisterEventHandler(ctrl domain.UserEventController) *RegisterEventHandler {
	return &RegisterEventHandler{ctrl: ctrl}
}

type registerEventRequest struct {
	UserID uint64 `json:"userId"  validate:"required" example:"46"`
	Type   string `json:"type" validate:"required,not_blank" enums:"register" example:"register"`
}

// _registerEventTypes defines the internal event types accepted by the HTTP contract.
var _registerEventTypes = []string{"register"}

// Handle triggers the new user registration event.
//
//	@Summary        Triggers the new user registration event
//	@Description    Triggers the new user registration event.
//	@Tags           internal
//	@Accept         json
//	@Produce        json
//	@Param          request body registerEventRequest true "User registration payload"
//	@Success        200 {object} commonHTTP.Response "Success."
//	@Failure        400 {object} commonHTTP.Response "Malformed JSON payload."
//	@Failure        422 {object} commonHTTP.Response "Validation errors in the request body."
//	@Failure        500 {object} commonHTTP.Response "Failed to trigger the event due to internal errors."
//	@Router         /api/v1/internal/users/events [post]
func (h RegisterEventHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	var req registerEventRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[RegisterEventHandler:Handle]") {
		return
	}

	if errResponse := decodeRegisterEventType("[RegisterEventHandler:Handle]", "type", req.Type); errResponse != nil {
		c.AbortWithStatusJSON(errResponse.HTTPStatus, commonHTTP.EncodeErrorResponse(ctx, errResponse))
		return
	}

	if errPublish := h.ctrl.PublishEventUserCreated(ctx, domain.UserCreatedEvent{
		UserID:     domain.NewIDFromUint64(req.UserID),
		OccurredAt: time.Now().UTC(),
	}); commonHTTP.AbortIfError(c, ctx, errPublish) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, nil))
}

// decodeRegisterEventType validates the internal registration event type.
func decodeRegisterEventType(scope, field, value string) *appErrors.ErrorResponse {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if slices.Contains(_registerEventTypes, normalized) {
		return nil
	}

	return svcErrors.NewOneOfValidationError(scope, field, value, _registerEventTypes)
}
