package users

import (
	"net/http"
	"slices"
	"time"

	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"
	svcHTTP "user-service/internal/transport/http"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	appErrors "github.com/whagency/core-common/errorsx"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
	commonTools "github.com/whagency/core-common/tools"
)

type UserRegisterHandler struct {
	ctrl domain.UserController
}

// NewUserRegisterHandler creates a new instance of UserRegisterHandler.
func NewUserRegisterHandler(c domain.UserController) *UserRegisterHandler {
	return &UserRegisterHandler{
		ctrl: c,
	}
}

type contactRequest struct {
	Type  string `json:"type" validate:"required,not_blank" enums:"email" example:"email"`
	Value string `json:"value" validate:"required,not_blank,contact_value" example:"test.email@gmail.com"`
}

// GetType returns the contact type.
func (c contactRequest) GetType() string {
	return c.Type
}

type userRegisterRequest struct {
	Contact   contactRequest `json:"contact" validate:"required"`
	Password  string         `json:"password" validate:"required,not_blank,password" example:"password"`
	Recaptcha string         `json:"recaptcha" validate:"required,not_blank" example:"recaptcha_token_value"`
}

type userRegisterResponse struct {
	ContactMasked string `json:"contactMasked" example:"te***@gmail.com"`
	TokenUUID     string `json:"tokenUUID" example:"0ea1fb64-7c54-43a6-bff9-f0ae1c0b19dc"`
	ExpiresAt     string `json:"expiresAt" example:"2026-03-02T06:31:43Z"`

	// CodeDelivered is false when registration succeeded but the verification code
	// could not be sent. The account exists and tokenUUID is valid; prompt the user
	// to resend via POST /api/v1/2fa/otp/resend rather than telling them to check
	// an inbox that will stay empty.
	CodeDelivered bool `json:"codeDelivered" example:"true"`
}

// _allowedContactTypes defines the contact types accepted by the registration HTTP contract.
var _allowedContactTypes = []domain.ContactType{
	domain.ContactTypeEmail,
}

// Handle user registration requests.
//
//	@Summary        Create a new user
//	@Description    Registers a new user, provisions credentials, and issues a contact verification challenge.
//	@Tags           users
//	@Accept         json
//	@Produce        json
//	@Param          request body userRegisterRequest true "Registration payload"
//	@Success        201 {object} commonHTTP.Response{data=userRegisterResponse} "User created and verification challenge issued."
//	@Failure        400 {object} commonHTTP.Response "Malformed payload or unsupported contact type."
//	@Failure        409 {object} commonHTTP.Response "Contact already registered or active verification in progress."
//	@Failure        422 {object} commonHTTP.Response "Validation errors in the request body."
//	@Failure        500 {object} commonHTTP.Response "Failed to persist user data due to internal errors."
//	@Router         /api/v1/users/register [post]
func (h UserRegisterHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	var req userRegisterRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[UserRegisterHandler:Handle]") {
		return
	}

	contactType, errResponse := decodeContactType("[UserRegisterHandler:Handle]", "contact.type", req.Contact.Type)
	if errResponse != nil {
		c.AbortWithStatusJSON(errResponse.HTTPStatus, commonHTTP.EncodeErrorResponse(ctx, errResponse))
		return
	}

	result, err := h.ctrl.Register(ctx, req.toDomain(c, contactType))
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusCreated, commonHTTP.EncodeSuccessResponse(ctx, encodeUserRegisterResponse(result)))
}

// toDomain converts userRegisterRequest to domain.UserRegisterParams.
func (r *userRegisterRequest) toDomain(c *gin.Context, contactType domain.ContactType) domain.UserRegisterParams {
	return domain.UserRegisterParams{
		SessionClientDeviceData: svcHTTP.NewSessionClientDeviceData(c),
		Contact: domain.ContactInput{
			Type:  contactType,
			Value: r.Contact.Value,
		},
		Password:  r.Password,
		Recaptcha: r.Recaptcha,
	}
}

// decodeContactType validates and converts the registration contact type.
func decodeContactType(scope, field, value string) (domain.ContactType, *appErrors.ErrorResponse) {
	contactType, err := domain.NewContactTypeFromString(value)
	if err == nil && slices.Contains(_allowedContactTypes, contactType) {
		return contactType, nil
	}

	return 0, svcErrors.NewOneOfValidationError(scope, field, value, commonTools.StringValues(_allowedContactTypes))
}

// encodeUserRegisterResponse encodes the user into a response format.
func encodeUserRegisterResponse(res domain.UserRegistrationResult) userRegisterResponse {
	return userRegisterResponse{
		ContactMasked: res.ContactMethod.GetMaskedContactValue(),
		TokenUUID:     res.TokenUUID,
		ExpiresAt:     res.ExpiresAt.Format(time.RFC3339),
		CodeDelivered: res.CodeDelivered,
	}
}
