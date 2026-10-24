package two_fa

import (
	"time"

	"user-service/internal/domain"
	svcErrors "user-service/internal/domain/errors"

	appErrors "github.com/whagency/core-common/errorsx"
	commonTools "github.com/whagency/core-common/tools"
	"slices"
)

// DecodeTwoFactorTokenType validates and converts a request token type within the allowed subset.
func DecodeTwoFactorTokenType(scope, field, value string, allowedValues []domain.TwoFactorTokenType) (domain.TwoFactorTokenType, *appErrors.ErrorResponse) {
	tokenType, err := domain.NewTwoFactorTokenTypeFromString(value)
	if err == nil && slices.Contains(allowedValues, tokenType) {
		return tokenType, nil
	}

	return 0, svcErrors.NewOneOfValidationError(scope, field, value, commonTools.StringValues(allowedValues))
}

type TwoFactorChallengeResponse struct {
	TokenUUID     string  `json:"tokenUUID" example:"06fd3021-b659-44e2-b86c-d45ec3fc75ac"`
	Method        string  `json:"method" example:"email"`
	Secret        string  `json:"secret,omitempty" example:"suhdfh9w43hr93h32h"`
	ExpiresAt     string  `json:"expiresAt" example:"2026-03-02T06:31:43Z"`
	ContactMasked *string `json:"contactMasked,omitempty" example:"2026-03-02T06:31:43Z"`
}

// EncodeTwoFactorChallengeResponse encodes domain.TwoFactorChallengeResult to twoFactorChallengeResponse
func EncodeTwoFactorChallengeResponse(res domain.TwoFactorChallengeResult) TwoFactorChallengeResponse {
	response := TwoFactorChallengeResponse{
		TokenUUID: res.TokenUUID,
		Method:    res.Method.String(),
		ExpiresAt: res.ExpiresAt.Format(time.RFC3339),
	}
	if res.Secret != "" {
		response.Secret = res.Secret
	}
	if res.ContactMethod != nil {
		contactMasked := res.ContactMethod.GetMaskedContactValue()
		response.ContactMasked = &contactMasked
	}

	return response
}
