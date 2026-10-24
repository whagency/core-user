package sessions

type SessionResponse struct {
	SessionID           string `json:"sessionId" example:"06fd3021-b659-44e2-b86c-d45ec3fc75ac"`
	AccessToken         string `json:"accessToken" example:"alskdjfhao874q48toa8wgfq76g49qfg"`
	AccessTokenExpires  string `json:"accessTokenExpiresAt" example:"2026-03-02T06:31:43Z"`
	RefreshToken        string `json:"refreshToken" example:"ahusdfigao87w478qr8gaogw84g"`
	RefreshTokenExpires string `json:"refreshTokenExpiresAt" example:"2026-03-02T06:31:43Z"`
}
