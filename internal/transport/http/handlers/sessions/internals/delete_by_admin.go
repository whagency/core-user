package internals

import (
	"net/http"

	"user-service/internal/domain"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
)

// DeleteSessionByAdminHandler revokes a specific session by an admin.
type DeleteSessionByAdminHandler struct {
	ctrl domain.SessionController
}

// NewDeleteSessionByAdminHandler builds a new DeleteSessionByAdminHandler instance.
func NewDeleteSessionByAdminHandler(ctrl domain.SessionController) *DeleteSessionByAdminHandler {
	return &DeleteSessionByAdminHandler{ctrl: ctrl}
}

type deleteSessionRequestURLParams struct {
	SessionID string `uri:"sessionId" validate:"required,uuid4" example:"06fd3021-b659-44e2-b86c-d45ec3fc75ac"`
}

type deleteSessionResponse struct {
	SessionID string `json:"sessionId" example:"06fd3021-b659-44e2-b86c-d45ec3fc75ac"`
}

// Handle revokes the user session by admin.
//
//	@Summary        Revoke a session (admin)
//	@Description    Allows privileged callers to revoke any user session by its identifier without ownership checks.
//	@Tags           internal
//	@Param          sessionId path string true "Session identifier"
//	@Produce        json
//	@Success        200 {object} commonHTTP.Response{data=deleteSessionResponse} "Session revoked."
//	@Failure        400 {object} commonHTTP.Response "Missing or malformed session identifier."
//	@Failure        401 {object} commonHTTP.Response "Missing or invalid administrative credentials."
//	@Failure        404 {object} commonHTTP.Response "Session not found or already revoked."
//	@Failure        500 {object} commonHTTP.Response "Failed to revoke the session due to internal errors."
//	@Router         /api/v1/internal/sessions/{sessionId} [delete]
func (h DeleteSessionByAdminHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	var params deleteSessionRequestURLParams
	if !commonValidation.BindAndValidateURI(c, httpValidation.Validator(), &params, "[DeleteSessionByAdminHandler:Handle]") {
		return
	}

	err := h.ctrl.RevokeSessionByAdmin(ctx, domain.SessionID(params.SessionID))
	if commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, deleteSessionResponse{SessionID: params.SessionID}))
}
