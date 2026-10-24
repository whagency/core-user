package amlbot

import (
	"github.com/imroc/req/v3"
	jsoniter "github.com/json-iterator/go"
)

type Service struct {
	client *req.Client
}

// NewAmlBotService creates a new instance of Service.
func NewAmlBotService(client *req.Client) *Service {
	return &Service{client: client}
}

type amlBotErrResponse struct {
	Type   string              `json:"type"`
	Errors jsoniter.RawMessage `json:"errors"`
}
