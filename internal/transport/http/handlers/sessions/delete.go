package sessions

import (
	"net/http"

	"user-service/internal/domain"
	httpHandlers "user-service/internal/transport/http/handlers"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
)

// DeleteSessionHandler revokes a specific session for the authenticated user.
type DeleteSessionHandler struct {
	ctrl domain.SessionController
}

// NewDeleteSessionHandler builds a new DeleteSessionHandler instance.
func NewDeleteSessionHandler(ctrl domain.SessionController) *DeleteSessionHandler {
	return &DeleteSessionHandler{ctrl: ctrl}
}

type deleteSessionRequestURLParams struct {
	SessionID string `uri:"sessionId" validate:"required,uuid4" example:"06fd3021-b659-44e2-b86c-d45ec3fc75ac"`
}

type deleteSessionResponse struct {
	SessionID string `json:"sessionId" example:"06fd3021-b659-44e2-b86c-d45ec3fc75ac"`
}

// Handle revokes the requested session if it belongs to the user.
//
//	@Summary        Revoke a session
//	@Description    Revokes a specific session by its identifier. Only sessions owned by the caller can be revoked.
//	@Tags           auth
//	@Security       Authorization
//	@Param          sessionId path string true "Session identifier"
//	@Produce        json
//	@Success        200 {object} commonHTTP.Response{data=deleteSessionResponse} "Session revoked."
//	@Failure        400 {object} commonHTTP.Response "Missing or malformed session identifier."
//	@Failure        401 {object} commonHTTP.Response "Missing or invalid access token."
//	@Failure        403 {object} commonHTTP.Response "Session does not belong to the authenticated user."
//	@Failure        404 {object} commonHTTP.Response "Session not found or already revoked."
//	@Failure        500 {object} commonHTTP.Response "Failed to revoke the session due to internal errors."
//	@Router         /api/v1/auth/sessions/{sessionId} [delete]
func (h DeleteSessionHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	session, ok := httpHandlers.RequireAuthenticatedSession(c, "[DeleteSessionHandler:Handle]")
	if !ok {
		return
	}

	var params deleteSessionRequestURLParams
	if !commonValidation.BindAndValidateURI(c, httpValidation.Validator(), &params, "[DeleteSessionHandler:Handle]") {
		return
	}

	if err := h.ctrl.RevokeSession(ctx, session, domain.SessionID(params.SessionID)); commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, deleteSessionResponse{SessionID: params.SessionID}))
}
