package domain

import (
	"context"
	"time"

	"github.com/whagency/core-common/cache"
)

const RevokedSessionCacheKeyID cache.KeyID = iota + 1

const RevokedSessionConfigCacheKey = "revoked_session"

var CacheConfigKeyIDs = map[string]cache.KeyID{
	RevokedSessionConfigCacheKey: RevokedSessionCacheKeyID,
}

var CacheKeys = map[cache.KeyID]*cache.Key{
	RevokedSessionCacheKeyID: {
		ID:   RevokedSessionCacheKeyID,
		Name: "revoked_session",
	},
}

// CacheRepository defines the operations for a cacheable repository
type CacheRepository[T cache.Cacheable] interface {
	Get(ctx context.Context, key string) (T, error)
	Exists(ctx context.Context, key string) (bool, error)
	Update(ctx context.Context, key string, data T) error
	UpdateWithTTL(ctx context.Context, key string, data T, ttl time.Duration) error
	GetWithRefresh(ctx context.Context, key string) (T, error)
	RefreshAndGet(ctx context.Context, key string) (T, error)
	DeleteKey(ctx context.Context, key string) error
}
