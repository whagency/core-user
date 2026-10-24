package protected

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"
	httpHandlers "user-service/internal/transport/http/handlers"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	appErrors "github.com/whagency/core-common/errorsx"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
)

// UpdateProfileHandler provides an example of a session-protected endpoint.
type UpdateProfileHandler struct {
	ctrl domain.UserController
}

// NewUpdateProfileHandler builds a new UpdateProfileHandler instance.
func NewUpdateProfileHandler(c domain.UserController) *UpdateProfileHandler {
	return &UpdateProfileHandler{
		ctrl: c,
	}
}

type updateProfileRequest struct {
	FirstName   *string `json:"firstName" example:"Robert"`
	LastName    *string `json:"lastName" example:"Vex"`
	DateOfBirth *string `json:"dob" example:"1986-01-02"`
	Address     *string `json:"address" example:"c. Dnipro, Ukraine, 01000, Kyiv, Kyivska street, 123"`
	Locale      *string `json:"locale" example:"en_US"`
	Timezone    *string `json:"timezone" example:"Europe/Kyiv"`
}

// Handle accepts a profile update payload and demonstrates how authenticated sessions are available downstream.
//
//	@Summary        Update profile
//	@Description    Updates the authenticated user's profile metadata (name, locale, and preferences).
//	@Tags           users
//	@Security       Authorization
//	@Accept         json
//	@Produce        json
//	@Param          request body updateProfileRequest true "Update profile payload"
//	@Success        200 {object} commonHTTP.Response "Profile updated."
//	@Failure        400 {object} commonHTTP.Response "Malformed JSON payload."
//	@Failure        401 {object} commonHTTP.Response "Missing or invalid access token."
//	@Failure        404 {object} commonHTTP.Response "Profile not found."
//	@Failure        422 {object} commonHTTP.Response "Validation errors in the request body."
//	@Failure        500 {object} commonHTTP.Response "Failed to update the profile due to internal errors."
//	@Router         /api/v1/users/update-profile [patch]
func (h UpdateProfileHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	session, ok := httpHandlers.RequireAuthenticatedSession(c, "[UpdateProfileHandler:Handle]")
	if !ok {
		return
	}

	var req updateProfileRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[UpdateProfileHandler:Handle]") {
		return
	}

	params, errResponse := req.decode("[UpdateProfileHandler:Handle]", session)
	if errResponse != nil {
		c.AbortWithStatusJSON(errResponse.HTTPStatus, commonHTTP.EncodeErrorResponse(ctx, errResponse))
		return
	}

	if err := h.ctrl.UpdateProfile(ctx, params); commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, nil))
}

// decode normalizes and validates the profile update payload before it reaches the controller.
func (r updateProfileRequest) decode(scope string, session domain.AuthenticatedSession) (domain.UpdateProfileParams, *appErrors.ErrorResponse) {
	validation := updateProfileValidation{}
	transportValidator := httpValidation.Validator()

	params := domain.UpdateProfileParams{UserID: session.UserID}
	params.FirstName = validation.optionalText("firstName", r.FirstName, 2, 64)
	params.LastName = validation.optionalText("lastName", r.LastName, 2, 64)
	params.Address = validation.optionalText("address", r.Address, 0, 150)
	params.DateOfBirth = validation.optionalDate("dob", r.DateOfBirth)
	params.Locale = validation.optionalValidatedText("locale", r.Locale, "locale", transportValidator, func(value string) string {
		return strings.ReplaceAll(value, "-", "_")
	})
	params.Timezone = validation.optionalValidatedText("timezone", r.Timezone, "timezone", transportValidator, nil)

	if errResponse := validation.err(scope); errResponse != nil {
		return domain.UpdateProfileParams{}, errResponse
	}

	return params, nil
}

type updateProfileValidation struct {
	entries appErrors.ValidationData
}

// add appends a validation entry for the profile update payload.
func (v *updateProfileValidation) add(field, tag string, params ...string) {
	v.entries = append(v.entries, appErrors.NewValidationEntry(field, tag, params...))
}

// err builds a service validation error when at least one field validation failed.
func (v *updateProfileValidation) err(scope string) *appErrors.ErrorResponse {
	if len(v.entries) == 0 {
		return nil
	}

	return svcErrors.New(
		appErrors.ValidationError,
		appErrors.WithCause(fmt.Errorf("%s[err: invalid profile update payload]", scope)),
		appErrors.WithValidationData(v.entries),
	)
}

// optionalValue applies the patch semantics for optional strings:
// nil means "do not update", empty after trimming is invalid.
func (v *updateProfileValidation) optionalValue(field string, raw *string) (string, bool) {
	if raw == nil {
		return "", false
	}

	value := strings.TrimSpace(*raw)
	if value == "" {
		v.add(field, appErrors.ValidationTagRequired)
		return "", false
	}

	return value, true
}

// optionalText validates an optional free-text field and returns the normalized value.
func (v *updateProfileValidation) optionalText(field string, raw *string, minLen, maxLen int) *string {
	value, ok := v.optionalValue(field, raw)
	if !ok {
		return nil
	}

	valueLen := utf8.RuneCountInString(value)
	if minLen > 0 && valueLen < minLen {
		v.add(field, appErrors.ValidationTagMin, fmt.Sprintf("%d", minLen))
		return nil
	}
	if maxLen > 0 && valueLen > maxLen {
		v.add(field, appErrors.ValidationTagMax, fmt.Sprintf("%d", maxLen))
		return nil
	}

	return &value
}

// optionalDate validates an optional date in YYYY-MM-DD format and returns its normalized representation.
func (v *updateProfileValidation) optionalDate(field string, raw *string) *string {
	value, ok := v.optionalValue(field, raw)
	if !ok {
		return nil
	}

	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		v.add(field, appErrors.ValidationTagFormat)
		return nil
	}

	normalized := parsed.Format("2006-01-02")
	return &normalized
}

// optionalValidatedText validates an optional string through a named validator and returns the normalized value.
func (v *updateProfileValidation) optionalValidatedText(
	field string,
	raw *string,
	validatorTag string,
	transportValidator interface{ Var(any, string) error },
	normalize func(string) string,
) *string {
	value, ok := v.optionalValue(field, raw)
	if !ok {
		return nil
	}

	if normalize != nil {
		value = normalize(value)
	}

	if err := transportValidator.Var(value, validatorTag); err != nil {
		v.add(field, appErrors.ValidationTagFormat)
		return nil
	}

	return &value
}
