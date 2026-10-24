package protected

import (
	"net/http"

	"user-service/internal/domain"
	httpHandlers "user-service/internal/transport/http/handlers"
	twoFaHandlers "user-service/internal/transport/http/handlers/two_fa"
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
	TokenType string `json:"tokenType" validate:"required,not_blank" enums:"two_factor_setup,two_factor_disable" example:"two_factor_setup"`
}

// _protectedChallengeResendAllowedTokenTypes defines the challenge token types accepted by the authenticated resend endpoint.
var _protectedChallengeResendAllowedTokenTypes = []domain.TwoFactorTokenType{
	domain.TwoFactorTokenTypeTwoFactorSetup,
	domain.TwoFactorTokenTypeTwoFactorDisable,
}

// Handle reissues an 2FA OTP code for a challenge identified by its token UUID.
//
//	@Summary                Resend 2FA OTP challenge
//	@Description    Issues a new OTP for two-factor authentication challenges
//	@Tags                   2FA
//	@Security       Authorization
//	@Accept                 json
//	@Produce                json
//	@Param                  json    body    challengeResendRequest true    "OTP challenge resend payload"
//	@Success                200     {object}        commonHTTP.Response{data=twoFaHandlers.TwoFactorChallengeResponse} "OTP resent"
//	@Failure                400     {object}        commonHTTP.Response                     "Body bad format"
//	@Failure                404     {object}        commonHTTP.Response                     "Token not found"
//	@Failure                409     {object}        commonHTTP.Response                     "Concurrency conflict"
//	@Failure                422     {object}        commonHTTP.Response                     "Validation error"
//	@Failure                429     {object}        commonHTTP.Response                     "Resend rate limited"
//	@Router                 /api/v1/2fa/challenge/resend [post]
func (h ChallengeResendHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	var req challengeResendRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[ChallengeResendHandler:Handle]") {
		return
	}

	tokenType, errResponse := twoFaHandlers.DecodeTwoFactorTokenType(
		"[ChallengeResendHandler:Handle]",
		"tokenType",
		req.TokenType,
		_protectedChallengeResendAllowedTokenTypes,
	)
	if errResponse != nil {
		c.AbortWithStatusJSON(errResponse.HTTPStatus, commonHTTP.EncodeErrorResponse(ctx, errResponse))
		return
	}

	session, sessionExist := httpHandlers.RequireAuthenticatedSession(c, "[ChallengeResendHandler:Handle]")
	if !sessionExist {
		return
	}

	result, err := h.ctrl.ResendChallenge(ctx, req.toDomain(session.UserID, tokenType))
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, twoFaHandlers.EncodeTwoFactorChallengeResponse(result)))
}

// toDomain converts challengeResendRequest to domain.TwoFactorChallengeResendParams.
func (r *challengeResendRequest) toDomain(userID domain.ID, tokenType domain.TwoFactorTokenType) domain.TwoFactorChallengeResendParams {
	return domain.TwoFactorChallengeResendParams{
		TokenUUID: r.TokenUUID,
		Type:      tokenType,
		UserID:    userID,
	}
}
