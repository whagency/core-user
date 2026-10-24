package user

import (
	"context"
	"errors"
	"fmt"
	"math"

	"user-service/internal/domain"
	"user-service/internal/infrastructure/security/sessions"
	"user-service/internal/transport/grpc/pb/userv1"

	commonDecode "github.com/whagency/core-common/decode"
	"github.com/whagency/core-common/errorsx"
	"github.com/whagency/core-common/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
	userv1.UnimplementedUserServiceServer
	userCtrl      domain.UserController
	sessionHelper domain.SessionHelper
}

func NewService(userCtrl domain.UserController, sessionHelper domain.SessionHelper) *Service {
	return &Service{
		userCtrl:      userCtrl,
		sessionHelper: sessionHelper,
	}
}

// GetProfile retrieves the profile information of a user by their ID.
func (s *Service) GetProfile(ctx context.Context, req *userv1.GetProfileRequest) (*userv1.GetProfileResponse, error) {
	userID, errDecode := decodeGetProfileRequest(req)
	if errDecode != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("[grpc][UserService:GetProfile]%s", errDecode))
	}

	profile, err := s.userCtrl.GetProfile(ctx, userID)
	if err != nil {
		logger.LogCtx(ctx).Errorf("[grpc][UserService:GetProfile]%s", err)
		return nil, mapUserLookupError("[grpc][UserService:GetProfile]", err)
	}

	return encodeGetProfileResponse(profile), nil
}

// GetUserByNumber retrieves user information based on their unique number.
func (s *Service) GetUserByNumber(ctx context.Context, req *userv1.GetUserByNumberRequest) (*userv1.GetUserByNumberResponse, error) {
	number, errDecode := decodeGetUserByNumberRequest(req)
	if errDecode != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("[grpc][UserService:GetUserByNumber]%s", errDecode))
	}

	user, err := s.userCtrl.GetByNumber(ctx, number)
	if err != nil {
		logger.LogCtx(ctx).Errorf("[grpc][UserService:GetUserByNumber]%s", err)
		return nil, mapUserLookupError("[grpc][UserService:GetUserByNumber]", err)
	}

	return &userv1.GetUserByNumberResponse{
		UserId:               user.ID.Uint64(),
		Number:               user.Number,
		Status:               user.Status.String(),
		VerificationLevel:    user.VerificationLevel.String(),
		VerificationLevelMax: user.VerificationLevel.IsMax(),
	}, nil
}

// ValidateSession validates a session token for internal consumers and returns user context.
func (s *Service) ValidateSession(ctx context.Context, req *userv1.ValidateSessionRequest) (*userv1.ValidateSessionResponse, error) {
	params, errDecode := decodeValidateSessionRequest(req)
	if errDecode != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("[grpc][UserService:ValidateSession]%s", errDecode))
	}

	session, err := s.sessionHelper.Validate(ctx, params.Token, params.ValidateOptions)
	if err != nil {
		return nil, mapValidateSessionError(ctx, err)
	}

	profile, err := s.userCtrl.GetProfile(ctx, session.UserID)
	if err != nil {
		logger.LogCtx(ctx).Errorf("[grpc][UserService:ValidateSession]%s", err)
		return nil, mapUserLookupError("[grpc][UserService:ValidateSession]", err)
	}

	return encodeValidateSessionResponse(session, profile), nil
}

type validateSessionRequest struct {
	Token string
	domain.ValidateOptions
}

// decodeGetProfileRequest decodes GetProfileRequest to domain.ID.
func decodeGetProfileRequest(req *userv1.GetProfileRequest) (domain.ID, error) {
	if req == nil {
		return 0, fmt.Errorf("[err: request is required]")
	}
	if err := commonDecode.RequirePositiveUint64("user_id", req.GetUserId()); err != nil {
		return 0, err
	}

	return domain.NewIDFromUint64(req.GetUserId()), nil
}

// decodeGetUserByNumberRequest decodes GetUserByNumberRequest to int64.
func decodeGetUserByNumberRequest(req *userv1.GetUserByNumberRequest) (int64, error) {
	if req == nil {
		return 0, fmt.Errorf("[err: request is required]")
	}
	if err := commonDecode.RequirePositiveUint64("number", req.GetNumber()); err != nil {
		return 0, err
	}
	if req.GetNumber() > math.MaxInt64 {
		return 0, fmt.Errorf("[err: number exceeds max int64]")
	}

	return int64(req.GetNumber()), nil
}

// decodeValidateSessionRequest decodes ValidateSessionRequest to validateSessionRequest.
func decodeValidateSessionRequest(req *userv1.ValidateSessionRequest) (validateSessionRequest, error) {
	if req == nil {
		return validateSessionRequest{}, fmt.Errorf("[err: request is required]")
	}

	token, err := commonDecode.ParseRequiredString("token", req.GetToken())
	if err != nil {
		return validateSessionRequest{}, err
	}

	// The wire flag waives expiry and nothing else. AllowRevoked is not mapped
	// from the request and must not become mappable: a caller on the other side
	// of this contract has no standing to decide that a revoked session is still
	// good. is_expired_validation_skip keeps its name because renaming a proto
	// field is a change to every consumer; what it does is decided here.
	return validateSessionRequest{
		Token:           token,
		ValidateOptions: domain.ValidateOptions{AllowExpired: req.GetIsExpiredValidationSkip()},
	}, nil
}

// mapUserLookupError maps user lookup errors to appropriate gRPC status errors.
func mapUserLookupError(scope string, err error) error {
	if er, ok := errorsx.AsErrorResponse(err); ok {
		if er.Code == errorsx.RecordNotFoundError {
			return status.Error(codes.NotFound, fmt.Sprintf("%s[err: not found]", scope))
		}
	}

	return status.Error(codes.Internal, fmt.Sprintf("%s[err: internal error]", scope))
}

// mapValidateSessionError maps session validation errors to appropriate gRPC status errors.
func mapValidateSessionError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, sessions.ErrExpired), errors.Is(err, sessions.ErrRevoked):
		return status.Error(codes.Unauthenticated, "[grpc][UserService:ValidateSession][err: session is expired or revoked]")
	case isInvalidSessionTokenError(err):
		return status.Error(codes.InvalidArgument, "[grpc][UserService:ValidateSession][err: invalid session token]")
	default:
		logger.LogCtx(ctx).Errorf("[grpc][UserService:ValidateSession]%s", err)
		return status.Error(codes.Internal, "[grpc][UserService:ValidateSession][err: internal error]")
	}
}

// isInvalidSessionTokenError checks if the error is related to invalid session token.
func isInvalidSessionTokenError(err error) bool {
	return errors.Is(err, sessions.ErrMalformedToken) ||
		errors.Is(err, sessions.ErrBadHeader) ||
		errors.Is(err, sessions.ErrSignature) ||
		errors.Is(err, sessions.ErrIssuerMismatch) ||
		errors.Is(err, sessions.ErrSubjectInvalid) ||
		errors.Is(err, sessions.ErrMissingClaims) ||
		errors.Is(err, sessions.ErrUnsupportedAlg) ||
		errors.Is(err, sessions.ErrUnsupportedTyp)
}

// encodeGetProfileResponse encodes the domain.UserProfile into a response format.
func encodeGetProfileResponse(res domain.UserProfile) *userv1.GetProfileResponse {
	var contactType userv1.ContactType
	switch res.PrimaryContact.Type {
	case domain.ContactTypeEmail:
		contactType = userv1.ContactType_CONTACT_TYPE_EMAIL
	case domain.ContactTypePhone:
		contactType = userv1.ContactType_CONTACT_TYPE_PHONE
	default:
		contactType = userv1.ContactType_CONTACT_TYPE_EMAIL
	}

	var locale string
	if res.ProfileDetails.Locale != nil {
		locale = *res.ProfileDetails.Locale
	}

	return &userv1.GetProfileResponse{
		Locale:       locale,
		ContactType:  contactType,
		ContactValue: res.PrimaryContact.Value,
	}
}

// encodeValidateSessionResponse encodes the validated session and user profile into a response format.
func encodeValidateSessionResponse(session domain.AuthenticatedSession, profile domain.UserProfile) *userv1.ValidateSessionResponse {
	return &userv1.ValidateSessionResponse{
		SessionId: session.SessionID.String(),
		User: &userv1.ValidateSessionUser{
			Id:                profile.UserID.Uint64(),
			VerificationLevel: profile.VerificationLevel.String(),
			Country:           profile.ProfileDetails.Country,
			Timezone:          profile.ProfileDetails.Timezone,
			Locale:            profile.ProfileDetails.Locale,
			Status:            profile.Status.String(),
		},
	}
}
