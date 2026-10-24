package v3

import (
	"context"

	"user-service/config"

	"github.com/imroc/req/v3"
	commonHTTP "github.com/whagency/core-common/http"
	"github.com/whagency/core-common/logger"
)

type Service struct {
	client *req.Client
}

// NewRecaptchaV3Service creates a new instance of Service.
func NewRecaptchaV3Service(client *req.Client) *Service {
	return &Service{client: client}
}

type recaptchaResponse struct {
	Success     bool     `json:"success"`
	Score       float64  `json:"score"`
	Action      string   `json:"action"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

// IsTokenValid checks the recaptcha token on Google service.
func (s Service) IsTokenValid(ctx context.Context, token string) bool {
	var response recaptchaResponse

	// Bound this call without touching the shared client — see
	// commonHTTP.WithCallTimeout.
	ctx, cancel := commonHTTP.WithCallTimeout(ctx, config.Commons().TimeoutExtCall)
	defer cancel()

	res, err := s.client.
		R().
		SetContext(ctx).
		SetFormData(map[string]string{
			"secret":   config.Commons().RecaptchaSecretKey,
			"response": token,
		}).
		SetSuccessResult(&response).
		SetErrorResult(&response).
		Post(config.Commons().RecaptchaCheckUrl)

	if err != nil {
		logger.LogCtx(ctx).Debugf("[recaptcha][V3][Service:IsTokenValid][err: %s]", err)
		return false
	}

	if !res.IsSuccessState() {
		logger.LogCtx(ctx).Debugf("[recaptcha][V3][Service:IsTokenValid][status: %s]", res.Status)
		return false
	}

	if !response.Success {
		logger.LogCtx(ctx).Debugf("[recaptcha][V3][Service:IsTokenValid][error code: %v]", response.ErrorCodes)
		return false
	}

	if response.Score < config.Commons().RecaptchaMinScore {
		logger.LogCtx(ctx).Debugf("[recaptcha][V3][Service:IsTokenValid][low score: %f]", response.Score)
		return false
	}

	logger.LogCtx(ctx).Debugf("[recaptcha][V3][Service:IsTokenValid][response: %+v]", response)

	return response.Success
}
