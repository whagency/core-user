package http

import (
	"strings"

	"user-service/internal/domain"

	"github.com/gin-gonic/gin"
	"github.com/mssola/user_agent"
)

const _headerDeviceFingerprint = "X-Device-Fingerprint"

// NewSessionClientDeviceData extracts client device information from the provided IP address, user agent, and device fingerprint.
func NewSessionClientDeviceData(c *gin.Context) domain.SessionClientDeviceData {
	sc := domain.SessionClientDeviceData{
		IPAddress:         strings.TrimSpace(c.ClientIP()),
		UserAgent:         strings.TrimSpace(c.Request.UserAgent()),
		DeviceFingerprint: strings.TrimSpace(c.GetHeader(_headerDeviceFingerprint)),
	}

	uaParser := user_agent.New(sc.UserAgent)

	browserName, browserVersion := uaParser.Browser()
	browser := strings.TrimSpace(browserName)
	if browser != "" && browserVersion != "" {
		browser = strings.TrimSpace(browser + " " + browserVersion)
	}
	if browser == "" {
		browser = "Unknown"
	}
	sc.Browser = browser

	device := strings.TrimSpace(uaParser.OS())
	if device == "" {
		device = strings.TrimSpace(uaParser.Platform())
	}
	if device == "" {
		if uaParser.Mobile() {
			device = "Mobile"
		} else if uaParser.Bot() {
			device = "Bot"
		}
	}
	if device == "" {
		device = "Unknown"
	}
	sc.Device = device

	return sc
}
