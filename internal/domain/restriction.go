package domain

import (
	"context"

	"github.com/whagency/core-common/services"
	"github.com/whagency/core-common/services/restriction"
)

// RestrictionService defines the interface for restriction-related operations.
type RestrictionService interface {
	IsGeoAllow(context.Context, string, restriction.GeoFilterOperationType) (bool, error)
}

// RestrictionGRPCService defines the interface for restriction-related operations.
type RestrictionGRPCService interface {
	services.GRPCClientBase
	RestrictionService
}
