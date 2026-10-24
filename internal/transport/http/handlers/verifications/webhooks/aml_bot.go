package webhooks

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	kycProviders "user-service/config/kyc-providers"
	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	appErrors "github.com/whagency/core-common/errorsx"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
	"github.com/whagency/core-common/logger"
	commonTools "github.com/whagency/core-common/tools"
)

const _signatureAmlBotWebhookHeaderKey = "x-data-integrity"

const (
	amlBotStatusPending   string = "pending"
	amlBotStatusCompleted string = "completed"
)

const (
	amlBotTypeStatusChanged string = "VERIFICATION_STATUS_CHANGED"
	amlBotTypeCompleted     string = "VERIFICATION_COMPLETED"
)

type AmlBotWebhookHandler struct {
	ctrl domain.VerificationController
}

// NewAmlBotWebhookHandler creates a new instance of AmlBotWebhookHandler.
func NewAmlBotWebhookHandler(c domain.VerificationController) *AmlBotWebhookHandler {
	return &AmlBotWebhookHandler{
		ctrl: c,
	}
}

type amlBotWebhookRequest struct {
	Type      string                        `json:"type" validate:"required,not_blank" enums:"VERIFICATION_STATUS_CHANGED,VERIFICATION_COMPLETED" example:"VERIFICATION_COMPLETED"`
	Verified  bool                          `json:"verified" example:"true"`
	Status    string                        `json:"status" validate:"required,not_blank" enums:"pending,completed" example:"completed"`
	Applicant amlBotApplicantWebhookRequest `json:"applicant" validate:"required"`
}

type amlBotApplicantWebhookRequest struct {
	ExternalApplicantID string  `json:"external_applicant_id" validate:"required,not_blank" example:"iabsf7gw47wafaih3fwfhi4"`
	FirstName           *string `json:"first_name" example:"Robert"`
	LastName            *string `json:"last_name" example:"Vex"`
	Dob                 *string `json:"dob" example:"1986-01-02"`
}

// Handle requests from AML BOT KYC service.
//
//	@Summary        KYC service postback url
//	@Description    Url for updating user verification status for remote KYC service
//	@Tags           verifications
//	@Accept         json
//	@Produce        json
//
// @Param		x-data-integrity	header		string	true	"Signature used to verify the integrity of the payload."
//
//	@Param          request body amlBotWebhookRequest true "Postback payload"
//	@Router         /api/v1/verifications/aml-bot/webhook [post]
func (h AmlBotWebhookHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	if err := verifyAmlBotSignature(c); err != nil {
		logger.LogCtx(ctx).Errorf("[AmlBotWebhookHandler:Handle]%s", err)
		er := svcErrors.New(svcErrors.InvalidSignatureError)
		c.AbortWithStatusJSON(er.HTTPStatus, commonHTTP.EncodeErrorResponse(ctx, er))
		return
	}

	var req amlBotWebhookRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[AmlBotWebhookHandler:Handle]") {
		return
	}

	params, shouldProcess, errResponse := req.decode()
	if errResponse != nil {
		c.AbortWithStatusJSON(errResponse.HTTPStatus, commonHTTP.EncodeErrorResponse(ctx, errResponse))
		return
	}
	if !shouldProcess {
		logger.LogCtx(ctx).Warnf(
			"[AmlBotWebhookHandler:Handle][msg: unsupported aml bot webhook event ignored][type:%s][status:%s][verified:%t][externalApplicantID:%s]",
			req.Type,
			req.Status,
			req.Verified,
			strings.TrimSpace(req.Applicant.ExternalApplicantID),
		)
		c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, nil))
		return
	}

	if err := h.ctrl.Process(ctx, params); commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, nil))
}

// decode converts a supported AML Bot event payload to domain params.
func (r amlBotWebhookRequest) decode() (domain.VerificationProcessParams, bool, *appErrors.ErrorResponse) {
	status, shouldProcess := r.decodeStatus()
	if !shouldProcess {
		return domain.VerificationProcessParams{}, false, nil
	}

	return domain.VerificationProcessParams{
		ExternalID: strings.TrimSpace(r.Applicant.ExternalApplicantID),
		Provider:   domain.VerificationProvidersAmlBot,
		Status:     status,
		Profile:    r.decodeProfile(),
	}, true, nil
}

// decodeStatus converts a supported AML Bot event/status combination to domain.VerificationStatus.
func (r amlBotWebhookRequest) decodeStatus() (domain.VerificationStatus, bool) {
	if r.Type == amlBotTypeCompleted && r.Status == amlBotStatusCompleted {
		if r.Verified {
			return domain.VerificationStatusCompleteYes, true
		}
		return domain.VerificationStatusCompleteNo, true
	}
	if r.Type == amlBotTypeStatusChanged && r.Status == amlBotStatusPending {
		return domain.VerificationStatusPending, true
	}

	return 0, false
}

// decodeProfile converts AML Bot profile data to the internal update profile payload.
func (r amlBotWebhookRequest) decodeProfile() domain.UpdateProfileParams {
	return domain.UpdateProfileParams{
		FirstName: commonTools.TrimmedOrNil(r.Applicant.FirstName),
		LastName:  commonTools.TrimmedOrNil(r.Applicant.LastName),
	}
}

// verifyAmlBotSignature verifies the AML Bot webhook signature.
func verifyAmlBotSignature(c *gin.Context) error {
	// Get the signature from the request header
	signature := strings.TrimSpace(c.GetHeader(_signatureAmlBotWebhookHeaderKey))
	if signature == "" {
		return fmt.Errorf("[verifySignature][err: missing %s header]", _signatureAmlBotWebhookHeaderKey)
	}

	// Get the raw request body to validate the signature
	requestBody, err := c.GetRawData()
	if err != nil {
		return fmt.Errorf("[verifySignature][err: %w]", err)
	}

	payload := string(requestBody)
	c.Request.Body = io.NopCloser(strings.NewReader(payload)) // restore body for downstream usage

	// Validate the signature
	if !validateAmlBotSignature(signature, payload, kycProviders.AMLBot().AmlBotApiToken) {
		return fmt.Errorf("[verifySignature][err: invalid amlBot-signature]")
	}

	return nil
}

// validateAmlBotSignature validates the AML Bot signature.
// A raw request body should be encoded using Base64 encoding.
// A hash of the encoded request body should be created using algorithm HMAC (SHA-512) and API token as the secret key.
func validateAmlBotSignature(signatureHeader, payload, secret string) bool {
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))

	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write([]byte(b64))
	sum := mac.Sum(nil)

	gotBytes, err := hex.DecodeString(signatureHeader)
	if err != nil {
		return false
	}

	if !hmac.Equal(sum, gotBytes) {
		return false
	}

	return true
}
