package sessions

import (
	"net/http"
	"time"

	"user-service/internal/domain"
	httpHandlers "user-service/internal/transport/http/handlers"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
)

// ActiveSessionsHandler lists active sessions for the authenticated user.
type ActiveSessionsHandler struct {
	ctrl domain.SessionController
}

// NewActiveSessionsHandler builds a new ActiveSessionsHandler instance.
func NewActiveSessionsHandler(ctrl domain.SessionController) *ActiveSessionsHandler {
	return &ActiveSessionsHandler{ctrl: ctrl}
}

type sessionItem struct {
	SessionID string `json:"sessionId" example:"06fd3021-b659-44e2-b86c-d45ec3fc75ac"`
	IP        string `json:"ip" example:"156.88.90.111"`
	Agent     string `json:"agent" example:"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.3.1 Safari/605.1.15"`
	Browser   string `json:"browser" example:"Safari 26.3.1"`
	Device    string `json:"device" example:"Intel Mac OS X 10_15_7"`
	// CreatedAt is when this login began. It survives token refreshes, which
	// replace the session row.
	CreatedAt string `json:"createdAt" example:"2026-03-02T06:31:43Z"`
	// LastActivityAt is the last token refresh, so it trails the user's real
	// last request by at most one access-token lifetime.
	LastActivityAt *string `json:"lastActivityAt,omitempty" example:"2026-03-02T06:31:43Z"`
}

type listSessionsResponse struct {
	Sessions []sessionItem `json:"sessions"`
}

// Handle returns the list of active sessions for the user.
//
//	@Summary        List active sessions
//	@Description    Retrieves active sessions for the authenticated user including device and geo metadata.
//	@Tags           auth
//	@Security       Authorization
//	@Produce        json
//	@Success        200 {object} commonHTTP.Response{data=listSessionsResponse} "List of active sessions."
//	@Failure        401 {object} commonHTTP.Response "Missing or invalid access token."
//	@Failure        500 {object} commonHTTP.Response "Unable to retrieve sessions due to internal issues."
//	@Router         /api/v1/auth/sessions [get]
func (h ActiveSessionsHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	session, ok := httpHandlers.RequireAuthenticatedSession(c, "[SessionsHandler:Handle]")
	if !ok {
		return
	}

	sessions, err := h.ctrl.ListSessions(ctx, session.UserID)
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, encodeSessionsResponse(sessions)))
}

// encodeSessionsResponse encodes the sessions list result into a response format
func encodeSessionsResponse(sessions []domain.Session) listSessionsResponse {
	items := make([]sessionItem, 0, len(sessions))
	for _, s := range sessions {
		item := sessionItem{
			SessionID: s.UUID.String(),
			IP:        s.IPAddress,
			Agent:     s.UserAgent,
			Browser:   s.Browser,
			Device:    s.Device,
			CreatedAt: s.CreatedAt.Format(time.RFC3339),
		}
		if s.LastActivityAt != nil {
			lastActivityAt := (*s.LastActivityAt).Format(time.RFC3339)
			item.LastActivityAt = &lastActivityAt
		}
		items = append(items, item)
	}

	return listSessionsResponse{Sessions: items}
}
