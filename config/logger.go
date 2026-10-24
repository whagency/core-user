package config

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
	"github.com/whagency/core-common/logger"
)

var loggerConfig logger.Config

// loadLoggerConfig loads the logger configuration from the environment variables
func loadLoggerConfig() error {
	// Set the environment for logger configuration
	loggerConfig.AppName = Commons().AppName
	loggerConfig.Environment = Commons().Environment
	loggerConfig.Version = Commons().Version

	if err := envconfig.Process("", &loggerConfig); err != nil {
		return fmt.Errorf("[loadLoggerConfig][err: %w]", err)
	}

	return nil
}

// LoggerConfig returns the logger configuration
func LoggerConfig() logger.Config {
	return loggerConfig
}
