package protected

import (
	"net/http"

	"user-service/internal/domain"
	httpHandlers "user-service/internal/transport/http/handlers"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
)

type VerificationInitHandler struct {
	ctrl domain.VerificationController
}

// NewVerificationInitHandler builds a new VerificationInitHandler instance.
func NewVerificationInitHandler(ctrl domain.VerificationController) *VerificationInitHandler {
	return &VerificationInitHandler{
		ctrl: ctrl,
	}
}

type verificationInitResponse struct {
	ProviderData any `json:"providerData,omitempty" swaggertype:"object,string" example:"form_url:https://kyc-forms-new.amlbot.com/qbcyr943yvr83qyt93y9y49y8v39y49yv94"` // This is a placeholder for any additional data that may be returned by the kyc provider.
}

// Handle requests a KYC init for an unverified user.
//
//	@Summary        Initialize KYC verification
//	@Description    Requests a KYC verification for an unverified user.
//	@Tags           verifications
//	@Accept         json
//	@Produce        json
//	@Success        200 {object} commonHTTP.Response{data=verificationInitResponse} "Verification created and returned external form link."
//	@Failure        400 {object} commonHTTP.Response "Error requesting external KYC service."
//	@Failure        401 {object} commonHTTP.Response "Missing or invalid access token."
//	@Failure        409 {object} commonHTTP.Response "User already verified or verification in progress."
//	@Failure        500 {object} commonHTTP.Response "Failed to save verification data due to internal errors."
//	@Router         /api/v1/verifications/init [post]
func (h VerificationInitHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	session, ok := httpHandlers.RequireAuthenticatedSession(c, "[VerificationInitHandler:Handle]")
	if !ok {
		return
	}

	result, err := h.ctrl.Init(ctx, domain.VerificationInitParams{
		UserID:   session.UserID,
		Provider: domain.VerificationProvidersAmlBot,
	})
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, encodeVerificationInitResponse(result)))
}

// encodeVerificationInitResponse encodes the domain.VerificationInitResult into a response format.
func encodeVerificationInitResponse(res domain.VerificationInitResult) verificationInitResponse {
	return verificationInitResponse{
		ProviderData: res.ProviderData,
	}
}
