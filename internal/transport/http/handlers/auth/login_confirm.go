package auth

import (
	"net/http"
	"time"

	"user-service/internal/domain"
	svcHTTP "user-service/internal/transport/http"
	sessionHandlers "user-service/internal/transport/http/handlers/sessions"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
)

// LoginChallengeConfirmHandler finalizes logins that require a second factor.
type LoginChallengeConfirmHandler struct {
	ctrl domain.AuthController
}

// NewLoginChallengeConfirmHandler builds a new LoginChallengeConfirmHandler instance.
func NewLoginChallengeConfirmHandler(ctrl domain.AuthController) *LoginChallengeConfirmHandler {
	return &LoginChallengeConfirmHandler{ctrl: ctrl}
}

type loginChallengeConfirmRequest struct {
	TokenUUID string `json:"tokenUUID" validate:"required,uuid4" example:"06fd3021-b659-44e2-b86c-d45ec3fc75ac"`
	Code      string `json:"code" validate:"required,not_blank,numeric_code,min=4,max=12" example:"331710"`
}

type loginChallengeConfirmResponse struct {
	Session sessionHandlers.SessionResponse `json:"session"`
}

// Handle validates the submitted challenge and issues session tokens.
//
//	@Summary        Confirm login challenge
//	@Description    Verifies a one-time 2FA challenge issued during login and, on success, returns fresh session tokens.
//	@Tags           auth
//	@Accept         json
//	@Produce        json
//	@Param          request body loginChallengeConfirmRequest true "Login challenge payload"
//	@Success        200 {object} commonHTTP.Response{data=loginChallengeConfirmResponse} "Challenge resolved and session issued."
//	@Failure        400 {object} commonHTTP.Response "Malformed JSON payload."
//	@Failure        401 {object} commonHTTP.Response "Invalid or expired challenge code."
//	@Failure        404 {object} commonHTTP.Response "Challenge or user record not found."
//	@Failure        409 {object} commonHTTP.Response "Concurrency conflict while consuming the challenge."
//	@Failure        422 {object} commonHTTP.Response "Validation errors in the request body."
//	@Failure        429 {object} commonHTTP.Response "Maximum verification attempts exceeded."
//	@Failure        500 {object} commonHTTP.Response "Unexpected error while issuing the session."
//	@Router         /api/v1/auth/login/challenge/confirm [post]
func (h LoginChallengeConfirmHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	var req loginChallengeConfirmRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[LoginChallengeConfirmHandler:Handle]") {
		return
	}

	result, err := h.ctrl.CompleteLoginChallenge(ctx, domain.LoginChallengeVerifyParams{
		TokenUUID:               req.TokenUUID,
		Code:                    req.Code,
		SessionClientDeviceData: svcHTTP.NewSessionClientDeviceData(c),
	})
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, loginChallengeConfirmResponse{
		Session: sessionHandlers.SessionResponse{
			SessionID:           result.Session.SessionID.String(),
			AccessToken:         result.Session.AccessToken,
			AccessTokenExpires:  result.Session.AccessExpiresAt.Format(time.RFC3339),
			RefreshToken:        result.Session.RefreshToken,
			RefreshTokenExpires: result.Session.RefreshExpiresAt.Format(time.RFC3339),
		},
	}))
}
