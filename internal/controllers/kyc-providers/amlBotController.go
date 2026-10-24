package kyc_providers

import (
	"context"
	"fmt"

	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"

	appErrors "github.com/whagency/core-common/errorsx"
	"github.com/whagency/core-common/logger"
)

type AmlBotCtrl struct {
	amlBot domain.AmlBotService
}

// NewAmlBotController creates a new instance of AmlBotCtrl.
func NewAmlBotController(
	amlBot domain.AmlBotService,
) *AmlBotCtrl {
	return &AmlBotCtrl{
		amlBot: amlBot,
	}
}

// InitRequest initializes a KYC verification request with the AmlBot service.
func (c AmlBotCtrl) InitRequest(ctx context.Context, verification *domain.Verification, verificationLevel domain.VerificationLevel) (domain.ProviderInitRequestResult, error) {
	logger.LogCtx(ctx).Debugf(
		"[AmlBotCtrl:InitRequest][verificationID:%d][userID:%d][provider:%s][status:%s][level:%s]",
		verification.ID,
		verification.UserID,
		verification.Provider.String(),
		verification.Status.String(),
		verificationLevel.String(),
	)

	providerData, err := c.amlBot.GetFormUrl(ctx, verification.ExternalID, verificationLevel)
	if err != nil {
		return domain.ProviderInitRequestResult{}, svcErrors.New(
			appErrors.ExternalServiceError,
			appErrors.WithCause(fmt.Errorf("[AmlBotCtrl:InitRequest]%w", err)),
		)
	}

	return providerData, nil
}
