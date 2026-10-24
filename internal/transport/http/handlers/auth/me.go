package auth

import (
	"net/http"
	"time"

	"user-service/internal/domain"
	httpHandlers "user-service/internal/transport/http/handlers"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
)

// MeHandler returns information about the authenticated user.
type MeHandler struct {
	ctrl domain.AuthController
}

// NewMeHandler builds a new MeHandler instance.
func NewMeHandler(ctrl domain.AuthController) *MeHandler {
	return &MeHandler{ctrl: ctrl}
}

type meContactResponse struct {
	Type       string  `json:"type" example:"email"`
	Value      string  `json:"value" example:"test.email@gmail.com"`
	Status     string  `json:"status" example:"verified"`
	IsPrimary  bool    `json:"isPrimary" example:"true"`
	VerifiedAt *string `json:"verifiedAt,omitempty" example:"2026-03-02T06:31:43Z"`
}

type meProfileResponse struct {
	FirstName   *string `json:"firstName,omitempty" example:"Robert"`
	LastName    *string `json:"lastName,omitempty" example:"Vex"`
	Country     string  `json:"country" example:"Ukraine"`
	DateOfBirth *string `json:"dateOfBirth,omitempty" example:"1983-03-02"`
	Address     *string `json:"address,omitempty" example:"Dnipro, Ukraine, 01000, Bulvar 1, 1-ya st., 10"`
	Locale      *string `json:"locale,omitempty" example:"uk_UA"`
	Timezone    *string `json:"timezone,omitempty" example:"Europe/Kiev"`
}

type meLastVerificationRequestResponse struct {
	FormUrl   string  `json:"formUrl" example:"https://kyc-forms-new.amlbot.com/qbcyr943yvr83qyt93y9y49y8v39y49yv94"`
	Status    string  `json:"status" example:"complete_yes"`
	CreatedAt string  `json:"createdAt" example:"2026-03-02T06:31:43Z"`
	UpdatedAt *string `json:"updatedAt,omitempty" example:"2026-03-02T06:31:43Z"`
}

type meResponse struct {
	UserNumber                  uint64                             `json:"userNumber" example:"45211983"`
	Status                      string                             `json:"status" example:"verified"`
	VerificationLevel           string                             `json:"verificationLevel" example:"basic"`
	Contact                     meContactResponse                  `json:"contact"`
	Profile                     meProfileResponse                  `json:"profile"`
	LastPasswordChangeAt        *string                            `json:"lastPasswordChangeAt,omitempty" example:"2026-03-02T06:31:43Z"`
	LastUserVerificationRequest *meLastVerificationRequestResponse `json:"lastUserVerificationRequest,omitempty"`
}

// Handle returns the authenticated user's information.
//
//	@Summary        Get current user
//	@Description    Returns the authenticated user's details, including primary contact and profile information.
//	@Tags           auth
//	@Security       Authorization
//	@Produce        json
//	@Success        200 {object} commonHTTP.Response{data=meResponse} "Current user data."
//	@Failure        401 {object} commonHTTP.Response "Missing or invalid access token."
//	@Failure        404 {object} commonHTTP.Response "User or related information not found."
//	@Failure        500 {object} commonHTTP.Response "Unexpected error while retrieving user information."
//	@Router         /api/v1/auth/me [get]
func (h MeHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	session, ok := httpHandlers.RequireAuthenticatedSession(c, "[MeHandler:Handle]")
	if !ok {
		return
	}

	result, err := h.ctrl.Me(ctx, session.UserID)
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, encodeMeResponse(result)))
}

// encodeMeResponse converts the domain.MeResult to a meResponse for API output.
func encodeMeResponse(res domain.MeResult) meResponse {
	var contact meContactResponse
	if res.Contact != nil {
		contact = meContactResponse{
			Type:      res.Contact.Type.String(),
			Value:     res.Contact.Value,
			Status:    res.Contact.Status.String(),
			IsPrimary: res.Contact.IsPrimary,
		}

		if res.Contact.VerifiedAt != nil {
			verifiedAt := res.Contact.VerifiedAt.Format(time.RFC3339)
			contact.VerifiedAt = &verifiedAt
		}
	}

	profile := meProfileResponse{
		Country: res.Profile.Country,
	}

	if res.Profile.FirstName != nil {
		profile.FirstName = res.Profile.FirstName
	}
	if res.Profile.LastName != nil {
		profile.LastName = res.Profile.LastName
	}
	if res.Profile.DateOfBirth != nil {
		date := res.Profile.DateOfBirth.Format(time.DateOnly)
		profile.DateOfBirth = &date
	}
	if res.Profile.Address != nil {
		profile.Address = res.Profile.Address
	}
	if res.Profile.Locale != nil {
		profile.Locale = res.Profile.Locale
	}
	if res.Profile.Timezone != nil {
		profile.Timezone = res.Profile.Timezone
	}

	response := meResponse{
		UserNumber:        res.UserNumber,
		Status:            res.Status,
		VerificationLevel: res.VerificationLevel.String(),
		Contact:           contact,
		Profile:           profile,
	}

	if res.LastPasswordChangeAt != nil {
		lastChange := res.LastPasswordChangeAt.Format(time.RFC3339)
		response.LastPasswordChangeAt = &lastChange
	}

	if res.LastUserVerificationRequest != nil {
		var updatedAt *string
		if res.LastUserVerificationRequest.UpdatedAt != nil {
			formatted := res.LastUserVerificationRequest.UpdatedAt.Format(time.RFC3339)
			updatedAt = &formatted
		}
		response.LastUserVerificationRequest = &meLastVerificationRequestResponse{
			FormUrl:   res.LastUserVerificationRequest.FormUrl,
			Status:    res.LastUserVerificationRequest.Status.String(),
			CreatedAt: res.LastUserVerificationRequest.CreatedAt.Format(time.RFC3339),
			UpdatedAt: updatedAt,
		}
	}

	return response
}
