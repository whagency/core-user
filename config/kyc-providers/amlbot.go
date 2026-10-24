package kyc_providers

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

var amlBotSettings AmlBotSettings

type AmlBotSettings struct {
	AmlBotURL            string `envconfig:"AML_BOT_URL" required:"true"`
	AmlBotApiToken       string `envconfig:"AML_BOT_API_TOKEN" required:"true"`
	AmlBotFormIDBasic    string `envconfig:"AML_BOT_FORM_ID_BASIC" required:"true"`
	AmlBotFormIDAdvanced string `envconfig:"AML_BOT_FORM_ID_ADVANCED" required:"true"`
	AmlBotFormIDPro      string `envconfig:"AML_BOT_FORM_ID_PRO" required:"true"`
}

// AMLBot returns the AML Bot settings
func AMLBot() AmlBotSettings {
	return amlBotSettings
}

// LoadAMLBotConfig loads the AML Bot configuration
func LoadAMLBotConfig() error {
	if err := envconfig.Process("", &amlBotSettings); err != nil {
		return fmt.Errorf("[kyc-providers][LoadAMLBotConfig][err: %w]", err)
	}
	return nil
}
