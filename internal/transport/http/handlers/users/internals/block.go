package internals

import (
	"net/http"

	"user-service/internal/domain"
	httpValidation "user-service/internal/transport/http/validation"

	"github.com/gin-gonic/gin"
	commonHTTP "github.com/whagency/core-common/http"
	commonValidation "github.com/whagency/core-common/http/validation"
)

// BlockUserHandler revokes all sessions associated with a user and blocks the user account.
type BlockUserHandler struct {
	userCtrl domain.UserController
}

// NewBlockUserHandler constructs a BlockUserHandler instance.
func NewBlockUserHandler(userCtrl domain.UserController) *BlockUserHandler {
	return &BlockUserHandler{
		userCtrl: userCtrl,
	}
}

type blockUserRequest struct {
	UserID uint64 `json:"userId"  validate:"required,gte=1" example:"12"`
}

// Handle revokes all sessions associated with the user and blocks it.
//
//	@Summary        Logout from all sessions and block user
//	@Description    Blocks the user account and revokes every session it holds, both in one transaction.
//	@Description    Returns 404 when no user has that id, rather than reporting success for a block that never happened.
//	@Tags           internal
//	@Accept         json
//	@Produce        json
//	@Param          request body blockUserRequest true "User ID payload"
//	@Success        200 {object} commonHTTP.Response{} "User logged out from all sessions and blocked."
//	@Failure        400 {object} commonHTTP.Response "Missing or malformed request payload."
//	@Failure        401 {object} commonHTTP.Response "Missing or invalid administrative credentials."
//	@Failure        404 {object} commonHTTP.Response "No user with that id."
//	@Failure        500 {object} commonHTTP.Response "Failed to logout and block user due to internal errors."
//	@Router         /api/v1/internal/users/block [post]
func (h BlockUserHandler) Handle(c *gin.Context) {
	ctx := c.Request.Context()

	var req blockUserRequest
	if ok := commonValidation.BindAndValidateJSON(c, httpValidation.Validator(), &req, "[BlockUserHandler:Handle]"); !ok {
		return
	}

	if err := h.userCtrl.Block(ctx, domain.NewIDFromUint64(req.UserID)); commonHTTP.AbortIfError(c, ctx, err) {
		return
	}

	c.JSON(http.StatusOK, commonHTTP.EncodeSuccessResponse(ctx, nil))
}
