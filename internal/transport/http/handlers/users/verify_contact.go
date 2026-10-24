package users

import (
	"net/http"

	"user-service/internal/domain"
	httpValidation "user-service/internal/transport/http/validation"

	commonValidation "github.com/whagency/core-common/http/validation"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
)

// VerifyContactHandler confirms contact verification challenges.
type VerifyContactHandler struct {
	ctrl domain.UserController
}

// NewVerifyContactHandler builds a new VerifyContactHandler instance.
func NewVerifyContactHandler(ctrl domain.UserController) *VerifyContactHandler {
	return &VerifyContactHandler{ctrl: ctrl}
}

type verifyContactRequest struct {
	TokenUUID string `json:"tokenUUID" validate:"required,uuid4" example:"0ea1fb64-7c54-43a6-bff9-f0ae1c0b19dc"`
	Code      string `json:"code" validate:"required,not_blank,numeric_code,min=4,max=12" example:"123765"`
}

// Handle validates the verification code and activates the user.
//
//	@Summary        Verify primary contact
//	@Description    Confirms the registration OTP and activates the user's account and primary contact.
//	@Tags           users
//	@Accept         json
//	@Produce        json
//	@Param          request body verifyContactRequest true "Contact verification payload"
//	@Success        200 {object} commonHTTP.Response "Contact verified."
//	@Failure        400 {object} commonHTTP.Response "Malformed JSON payload."
//	@Failure        401 {object} commonHTTP.Response "Invalid or expired verification code."
//	@Failure        404 {object} commonHTTP.Response "Verification challenge not found."
//	@Failure        409 {object} commonHTTP.Response "Contact already verified or concurrency conflict detected."
//	@Failure        422 {object} commonHTTP.Response "Validation errors in the request body."
//	@Failure        429 {object} commonHTTP.Response "Maximum verification attempts exceeded."
//	@Failure        500 {object} commonHTTP.Response "Failed to verify the contact due to internal errors."
//	@Router         /api/v1/users/verify-contact [post]
func (h VerifyContactHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	var req verifyContactRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[VerifyContactHandler:Handle]") {
		return
	}

	if err := h.ctrl.VerifyContact(ctx, domain.ContactVerifyParams{TokenUUID: req.TokenUUID, Code: req.Code}); commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, nil))
}
