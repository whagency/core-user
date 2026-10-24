package auth

import (
	"net/http"
	"time"

	"user-service/internal/domain"
	svcHTTP "user-service/internal/transport/http"
	sessionHandlers "user-service/internal/transport/http/handlers/sessions"
	"user-service/internal/transport/http/handlers/two_fa"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
)

// LoginHandler handles credential based authentication requests.
type LoginHandler struct {
	ctrl domain.AuthController
}

// NewLoginHandler builds a new LoginHandler instance.
func NewLoginHandler(ctrl domain.AuthController) *LoginHandler {
	return &LoginHandler{
		ctrl: ctrl,
	}
}

type loginRequest struct {
	Identifier string `json:"identifier" validate:"required,not_blank,min=5,max=255,identifier" example:"email"` // email or phone
	Password   string `json:"password" validate:"required,not_blank" example:"password"`                         // password
	Recaptcha  string `json:"recaptcha" validate:"required,not_blank" example:"recaptcha_token"`                 // recaptcha
}

type loginResponse struct {
	Session            *sessionHandlers.SessionResponse   `json:"session,omitempty"`
	Requires2FA        bool                               `json:"requires2fa" example:"false"`
	TwoFactorChallenge *two_fa.TwoFactorChallengeResponse `json:"twoFactorChallenge,omitempty"`
}

// Handle processes a login request, validating credentials and returning session tokens.
//
//	@Summary        Authenticate with primary contact and password
//	@Description    Authenticates a user via email or phone and password. Returns either session tokens or a 2FA challenge when an additional factor is required.
//	@Tags           auth
//	@Accept         json
//	@Produce        json
//	@Param          request body loginRequest true "Login payload"
//	@Success        200 {object} commonHTTP.Response{data=loginResponse} "Authentication succeeded. Requires2FA=true when a secondary challenge must be completed."
//	@Failure        400 {object} commonHTTP.Response "Malformed JSON payload."
//	@Failure        401 {object} commonHTTP.Response "Invalid credentials or expired authentication challenge."
//	@Failure        403 {object} commonHTTP.Response "Account pending verification, blocked, contact unverified, or password rotation required."
//	@Failure        409 {object} commonHTTP.Response "Two-factor authentication already provisioned for the account."
//	@Failure        422 {object} commonHTTP.Response "Validation errors in the request body."
//	@Failure        500 {object} commonHTTP.Response "Unexpected internal error while processing the login request."
//	@Router         /api/v1/auth/login [post]
func (h LoginHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	var req loginRequest
	if !commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[LoginHandler:Handle]") {
		return
	}

	result, err := h.ctrl.Login(ctx, req.toDomain(c))
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, encodeLoginResponse(result)))
}

// toDomain converts the loginRequest to domain.LoginParams.
func (r loginRequest) toDomain(c *gin.Context) domain.LoginParams {
	return domain.LoginParams{
		Identifier:              r.Identifier,
		Password:                r.Password,
		Recaptcha:               r.Recaptcha,
		SessionClientDeviceData: svcHTTP.NewSessionClientDeviceData(c),
	}
}

// encodeLoginResponse encodes the login result into a response format
func encodeLoginResponse(res domain.LoginResult) loginResponse {
	loginRes := loginResponse{
		Requires2FA: res.Requires2FA,
	}

	if res.Session != nil {
		loginRes.Session = &sessionHandlers.SessionResponse{
			SessionID:           res.Session.SessionID.String(),
			AccessToken:         res.Session.AccessToken,
			AccessTokenExpires:  res.Session.AccessExpiresAt.Format(time.RFC3339),
			RefreshToken:        res.Session.RefreshToken,
			RefreshTokenExpires: res.Session.RefreshExpiresAt.Format(time.RFC3339),
		}
	}

	if res.TwoFactorChallengeResult != nil {
		challenge := two_fa.EncodeTwoFactorChallengeResponse(*res.TwoFactorChallengeResult)
		loginRes.TwoFactorChallenge = &challenge
	}

	return loginRes
}
