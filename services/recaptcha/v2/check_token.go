package v2

import (
	"context"
	"fmt"

	"user-service/config"

	"github.com/imroc/req/v3"
	commonHTTP "github.com/whagency/core-common/http"
	"github.com/whagency/core-common/logger"
	"github.com/whagency/core-common/tools"
)

const _recaptchaURL = "https://www.google.com/recaptcha/api/siteverify?secret=%s&response=%s"

type Service struct {
	client *req.Client
}

// NewRecaptchaV2Service creates a new instance of Service.
func NewRecaptchaV2Service(client *req.Client) *Service {
	return &Service{client: client}
}

type recaptchaResponse struct {
	Success bool `json:"success"`
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
		SetHeaders(map[string]string{
			tools.ContentTypeHeader: tools.JSONContentType,
		}).
		SetSuccessResult(&response).
		SetErrorResult(&response).
		Post(fmt.Sprintf(_recaptchaURL, config.Commons().RecaptchaSecretKey, token))

	if err != nil {
		logger.Log().Debugf("[recaptcha][V2][Service:IsTokenValid][err: %s]", err)
		return false
	}

	if !res.IsSuccessState() {
		return false
	}

	logger.Log().Debugf("[recaptcha][V2][Service:IsTokenValid][response:%+v]", response)

	return response.Success
}
