package two_fa

import (
	"net/http"

	"user-service/internal/domain"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
)

// ChallengeResendHandler handles OTP challenge resend requests.
type ChallengeResendHandler struct {
	ctrl domain.TwoFactorController
}

// NewChallengeResendHandler creates a new ChallengeResendHandler instance.
func NewChallengeResendHandler(ctrl domain.TwoFactorController) *ChallengeResendHandler {
	return &ChallengeResendHandler{ctrl: ctrl}
}

type challengeResendRequest struct {
	TokenUUID string `json:"tokenUUID" validate:"required,uuid4" example:"06fd3021-b659-44e2-b86c-d45ec3fc75ac"`
	TokenType string `json:"tokenType" validate:"required,not_blank" enums:"verify_contact,password_reset,two_factor_auth" example:"password_reset"`
}

// _otpChallengeResendAllowedTokenTypes defines the challenge token types accepted by the public resend endpoint.
var _otpChallengeResendAllowedTokenTypes = []domain.TwoFactorTokenType{
	domain.TwoFactorTokenTypeVerifyContact,
	domain.TwoFactorTokenTypePasswordReset,
	domain.TwoFactorTokenTypeTwoFactorAuth,
}

// Handle reissues an OTP for a challenge identified by its token UUID.
//
//	@Summary                Resend OTP challenge
//	@Description    Issues a new OTP for contact verification, login challenges, or password recovery tokens
//	@Tags                   2FA
//	@Accept                 json
//	@Produce                json
//	@Param                  json    body    challengeResendRequest true    "OTP challenge resend payload"
//	@Success                200     {object}        commonHTTP.Response{data=TwoFactorChallengeResponse} "OTP resent"
//	@Failure                400     {object}        commonHTTP.Response                     "Body bad format"
//	@Failure                404     {object}        commonHTTP.Response                     "Token not found"
//	@Failure                409     {object}        commonHTTP.Response                     "Concurrency conflict"
//	@Failure                422     {object}        commonHTTP.Response                     "Validation error"
//	@Failure                429     {object}        commonHTTP.Response                     "Resend rate limited"
//	@Router                 /api/v1/2fa/otp/resend [post]
func (h ChallengeResendHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	var req challengeResendRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[ChallengeResendHandler:Handle]") {
		return
	}

	tokenType, errResponse := DecodeTwoFactorTokenType(
		"[ChallengeResendHandler:Handle]",
		"tokenType",
		req.TokenType,
		_otpChallengeResendAllowedTokenTypes,
	)
	if errResponse != nil {
		c.AbortWithStatusJSON(errResponse.HTTPStatus, commonHTTP.EncodeErrorResponse(ctx, errResponse))
		return
	}

	result, err := h.ctrl.ResendChallenge(ctx, req.toDomain(tokenType))
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, EncodeTwoFactorChallengeResponse(result)))
}

// toDomain converts challengeResendRequest to domain.TwoFactorChallengeResendParams.
func (r *challengeResendRequest) toDomain(tokenType domain.TwoFactorTokenType) domain.TwoFactorChallengeResendParams {
	return domain.TwoFactorChallengeResendParams{
		TokenUUID: r.TokenUUID,
		Type:      tokenType,
	}
}
