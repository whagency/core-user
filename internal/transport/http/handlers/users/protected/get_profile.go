package protected

import (
	"net/http"
	"time"

	"user-service/internal/domain"
	httpHandlers "user-service/internal/transport/http/handlers"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
)

// GetProfileHandler provides an example of a profile data endpoint.
type GetProfileHandler struct {
	ctrl domain.UserController
}

// NewGetProfileHandler builds a new GetProfileHandler instance.
func NewGetProfileHandler(c domain.UserController) *GetProfileHandler {
	return &GetProfileHandler{
		ctrl: c,
	}
}

type getProfileLastVerificationRequestResponse struct {
	Status    string  `json:"status" example:"complete_yes"`
	CreatedAt string  `json:"createdAt" example:"2026-03-02T06:31:43Z"`
	UpdatedAt *string `json:"updatedAt,omitempty" example:"2026-03-02T06:31:43Z"`
}

type getProfilePrimaryContactResponse struct {
	Type   string `json:"type" example:"email"`
	Value  string `json:"value" example:"test.email@gmail.com"`
	Status string `json:"status" example:"verified"`
}

type getProfileResponse struct {
	UserNumber                  uint64                                     `json:"userNumber" example:"53221222"`
	VerificationLevel           string                                     `json:"verificationLevel" example:"basic"`
	VerificationLevelMax        bool                                       `json:"verificationLevelMax" example:"false"`
	Status                      string                                     `json:"status" example:"active"`
	Locale                      string                                     `json:"locale" example:"en-US"`
	LastUserVerificationRequest *getProfileLastVerificationRequestResponse `json:"lastUserVerificationRequest,omitempty"`
	PrimaryContact              getProfilePrimaryContactResponse           `json:"primaryContact"`
}

// Handle get user's profile data.
//
//	@Summary        Get user's profile data
//	@Description    Return the authenticated user's profile attributes and latest verification request metadata.
//	@Tags           users
//	@Security       Authorization
//	@Accept         json
//	@Produce        json
//	@Success        200 {object} commonHTTP.Response{data=getProfileResponse} "User's profile data."
//	@Failure        401 {object} commonHTTP.Response "Missing or invalid access token."
//	@Failure        404 {object} commonHTTP.Response "User not found."
//	@Failure        500 {object} commonHTTP.Response "Failed getting the profile due to internal errors."
//	@Router         /api/v1/users/get-profile [get]
func (h GetProfileHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	session, ok := httpHandlers.RequireAuthenticatedSession(c, "[GetProfileHandler:Handle]")
	if !ok {
		return
	}

	result, err := h.ctrl.GetProfile(ctx, session.UserID)
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, encodeGetProfileResponse(result)))
}

// encodeGetProfileResponse encodes the domain.UserProfile into a response format.
func encodeGetProfileResponse(res domain.UserProfile) getProfileResponse {
	var locale string
	if res.ProfileDetails.Locale != nil {
		locale = *res.ProfileDetails.Locale
	}
	response := getProfileResponse{
		UserNumber:           res.UserNumber,
		VerificationLevel:    res.VerificationLevel.String(),
		VerificationLevelMax: res.VerificationLevel.IsMax(),
		Status:               res.Status.String(),
		Locale:               locale,
		PrimaryContact: getProfilePrimaryContactResponse{
			Type:   res.PrimaryContact.Type.String(),
			Value:  res.PrimaryContact.Value,
			Status: res.PrimaryContact.Status.String(),
		},
	}
	if res.LastUserVerificationRequest != nil {
		var updatedAt *string
		if res.LastUserVerificationRequest.UpdatedAt != nil {
			formatted := res.LastUserVerificationRequest.UpdatedAt.Format(time.RFC3339)
			updatedAt = &formatted
		}
		response.LastUserVerificationRequest = &getProfileLastVerificationRequestResponse{
			Status:    res.LastUserVerificationRequest.Status.String(),
			CreatedAt: res.LastUserVerificationRequest.CreatedAt.Format(time.RFC3339),
			UpdatedAt: updatedAt,
		}
	}
	return response
}
