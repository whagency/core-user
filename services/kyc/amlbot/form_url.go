package amlbot

import (
	"context"
	"fmt"

	"user-service/config"
	kycProviders "user-service/config/kyc-providers"
	"user-service/internal/domain"

	commonHTTP "github.com/whagency/core-common/http"
	"github.com/whagency/core-common/logger"
	"github.com/whagency/core-common/tools"
)

const _getFormUrlURL = "/forms/%s/urls"

type getFormUrlRequest struct {
	ExternalApplicantID string `json:"external_applicant_id"`
}

type getFormUrlResponse struct {
	FormUrl string `json:"form_url"`
}

// decode converts getFormUrlResponse to domain.ProviderInitResult.
func (r getFormUrlResponse) decode() domain.ProviderInitRequestResult {
	return domain.ProviderInitRequestResult{
		ProviderData: r,
	}
}

// GetFormUrl retrieves the verification url from the aml bot service.
func (s Service) GetFormUrl(ctx context.Context, externalID string, verificationLevel domain.VerificationLevel) (domain.ProviderInitRequestResult, error) {
	var (
		response    getFormUrlResponse
		errResponse amlBotErrResponse
	)

	// Bound this call without touching the shared client — see
	// commonHTTP.WithCallTimeout.
	ctx, cancel := commonHTTP.WithCallTimeout(ctx, config.Commons().TimeoutExtCall)
	defer cancel()

	res, err := s.client.
		R().
		SetContext(ctx).
		SetHeaders(map[string]string{
			tools.ContentTypeHeader: tools.JSONContentType,
			"Authorization":         fmt.Sprintf("Token %s", kycProviders.AMLBot().AmlBotApiToken),
		}).
		SetBody(&getFormUrlRequest{ExternalApplicantID: externalID}).
		SetSuccessResult(&response).
		SetErrorResult(&errResponse).
		Post(kycProviders.AMLBot().AmlBotURL + fmt.Sprintf(_getFormUrlURL, verificationLevelToFormID(verificationLevel)))
	if err != nil {
		return domain.ProviderInitRequestResult{}, fmt.Errorf("[kyc][amlbot][Service:GetFormUrl][err:%w]", err)
	}
	if !res.IsSuccessState() {
		return domain.ProviderInitRequestResult{}, fmt.Errorf("[kyc][amlbot][Service:GetFormUrl][httpCode:%d][appErrType:%s]", res.StatusCode, errResponse.Type)
	}

	logger.Log().Debugf("[kyc][amlbot][Service:GetFormUrl][response:%+v]", response)

	return response.decode(), nil
}

// verificationLevelToFormID maps the verification level to AML service form ID.
func verificationLevelToFormID(verificationLevel domain.VerificationLevel) string {
	switch verificationLevel {
	case 1:
		return kycProviders.AMLBot().AmlBotFormIDBasic
	case 2:
		return kycProviders.AMLBot().AmlBotFormIDAdvanced
	case 3:
		return kycProviders.AMLBot().AmlBotFormIDPro
	default:
		return ""
	}
}
