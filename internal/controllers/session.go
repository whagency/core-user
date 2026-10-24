package controllers

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"
	svcErrors "user-service/internal/domain/errors"

	"user-service/internal/domain"

	"github.com/whagency/core-common/cache"
	appErrors "github.com/whagency/core-common/errorsx"
	"github.com/whagency/core-common/logger"
)

// SessionCtrl orchestrates user session management use cases.
type SessionCtrl struct {
	geoCtrl            domain.GeoController
	sessions           domain.SessionRepository
	revokedSessions    domain.RevokedSessionRepository
	authLogs           domain.AuthLogRepository
	revocationCache    domain.CacheRepository[domain.RevokedSession]
	sessionHelper      domain.SessionHelper
	transactionManager domain.TransactionManager
}

// NewSessionController builds a new session controller.
func NewSessionController(
	geoCtrl domain.GeoController,
	sessions domain.SessionRepository,
	revokedSessions domain.RevokedSessionRepository,
	authLogs domain.AuthLogRepository,
	revocationCache domain.CacheRepository[domain.RevokedSession],
	sessionHelper domain.SessionHelper,
	tm domain.TransactionManager,
) *SessionCtrl {
	return &SessionCtrl{
		geoCtrl:            geoCtrl,
		sessions:           sessions,
		revokedSessions:    revokedSessions,
		authLogs:           authLogs,
		revocationCache:    revocationCache,
		sessionHelper:      sessionHelper,
		transactionManager: tm,
	}
}

// Issue creates and persists a new session for the user.
func (c SessionCtrl) Issue(ctx context.Context, sessionIssueParams *domain.SessionIssueParams) (domain.SessionToken, error) {
	logger.LogCtx(ctx).Debugf(
		"[SessionCtrl:Issue][userID:%d][hasDeviceFingerprint:%t][hasIP:%t]",
		sessionIssueParams.UserID,
		sessionIssueParams.DeviceFingerprint != "",
		sessionIssueParams.IPAddress != "",
	)

	session, err := c.issueSession(ctx, sessionIssueParams)
	if err != nil {
		if err.Cause != nil {
			err.SetCause(fmt.Errorf("[SessionCtrl:Issue]%w", err.Cause))
		}
		return domain.SessionToken{}, err
	}

	return session, nil
}

// ListSessions returns persisted sessions for the user.
func (c SessionCtrl) ListSessions(ctx context.Context, userID domain.ID) ([]domain.Session, error) {
	logger.LogCtx(ctx).Debugf("[SessionCtrl:ListSessions][userID: %d]", userID)

	sessions, err := c.sessions.ListByUserID(ctx, userID)
	if err != nil {
		return nil, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[SessionCtrl:ListSessions]%w", err)),
		)
	}

	return sessions, nil
}

// RevokeSession revokes a specific session identified by sessionID.
func (c SessionCtrl) RevokeSession(ctx context.Context, session domain.AuthenticatedSession, sessionID domain.SessionID) error {
	logger.LogCtx(ctx).Debugf("[SessionCtrl:RevokeSession][userID:%d][sessionID:%s]", session.UserID, sessionID)

	return c.runTx(ctx, func(tx context.Context) error {
		stored, err := c.sessions.WithTxFromContext(tx).FindByUUID(tx, sessionID)
		if err != nil {
			if errors.Is(err, domain.ErrRecordNotFound) {
				return svcErrors.New(
					appErrors.RecordNotFoundError,
					appErrors.WithCause(fmt.Errorf("[SessionCtrl:RevokeSession]%w", err)),
				)
			}
			return svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[SessionCtrl:RevokeSession]%w", err)),
			)
		}

		if stored.UserID != session.UserID {
			return svcErrors.New(
				appErrors.AccessForbiddenError,
				appErrors.WithCause(fmt.Errorf("[SessionCtrl:RevokeSession][err: session not owned by user]")),
			)
		}

		if errRevoke := c.revokeAndCleanup(
			tx,
			newRevokedSessionFromDB(stored, domain.SessionRevocationReasonUserRevoke),
		); errRevoke != nil {
			if errRevoke.Cause != nil {
				errRevoke.SetCause(fmt.Errorf("[SessionCtrl:RevokeSession]%w", errRevoke.Cause))
			}
			return errRevoke
		}

		if errLog := c.authLogs.WithTxFromContext(tx).Create(tx, domain.NewAuthLog(session, domain.AuthLogStatusSessionRevoked)); errLog != nil {
			return svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[SessionCtrl:RevokeSession]%w", errLog)),
			)
		}

		return nil
	})
}

// RevokeSessionByAdmin revokes a specific session identified by sessionID without ownership check.
func (c SessionCtrl) RevokeSessionByAdmin(ctx context.Context, sessionID domain.SessionID) error {
	logger.LogCtx(ctx).Debugf("[SessionCtrl:RevokeSessionByAdmin][sessionID: %s]", sessionID)

	return c.runTx(ctx, func(tx context.Context) error {
		if er := c.revokeSessionByAdmin(tx, sessionID); er != nil {
			if er.Cause != nil {
				er.SetCause(fmt.Errorf("[SessionCtrl:RevokeSessionByAdmin]%w", er.Cause))
			}
			return er
		}
		return nil
	})
}

// RevokeAllOnBlock revokes every session the user holds, on the transaction
// already open in ctx.
//
// It runs on the caller's transaction rather than its own so that blocking an
// account and ending its sessions commit together. Separately, a failure between
// the two left the account flagged while its sessions kept working, and the
// status is only consulted at sign-in.
//
// The caller owes an open transaction and a cache clean map, the same as
// RevokeAllOnPasswordChange.
func (c SessionCtrl) RevokeAllOnBlock(ctx context.Context, userID domain.ID) *appErrors.ErrorResponse {
	logger.LogCtx(ctx).Debugf("[SessionCtrl:RevokeAllOnBlock][userID: %d]", userID)

	_, errRevoke := c.revokeAllSessions(ctx, userID, domain.SessionRevocationReasonAdminKick, "")
	if errRevoke != nil {
		if errRevoke.Cause != nil {
			errRevoke.SetCause(fmt.Errorf("[SessionCtrl:RevokeAllOnBlock]%w", errRevoke.Cause))
		}
		return errRevoke
	}

	return nil
}

// Logout revokes the currently authenticated session.
func (c SessionCtrl) Logout(ctx context.Context, session domain.AuthenticatedSession) error {
	logger.LogCtx(ctx).Debugf("[SessionCtrl:Logout][sessionID:%s][userID:%d]", session.SessionID, session.UserID)

	expAt := func() *time.Time {
		if session.ExpiresAt.IsZero() {
			return nil
		}
		e := session.ExpiresAt
		return &e
	}()

	return c.runTx(ctx, func(tx context.Context) error {
		if err := c.revokeAndCleanup(
			tx,
			newRevokedSession(session, expAt),
		); err != nil {
			if err.Cause != nil {
				err.SetCause(fmt.Errorf("[SessionCtrl:Logout]%w", err.Cause))
			}
			return err
		}

		if errLog := c.authLogs.WithTxFromContext(tx).Create(tx, domain.NewAuthLog(session, domain.AuthLogStatusLogout)); errLog != nil {
			return svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[SessionCtrl:Logout]%w", errLog)),
			)
		}

		return nil
	})
}

// LogoutAll revokes every active session belonging to the user, the one making
// the request included.
func (c SessionCtrl) LogoutAll(ctx context.Context, session domain.AuthenticatedSession) error {
	logger.LogCtx(ctx).Debugf("[SessionCtrl:LogoutAll][userID:%d]", session.UserID)

	return c.runTx(ctx, func(tx context.Context) error {
		if _, errRevoke := c.revokeAllSessions(
			tx,
			session.UserID,
			domain.SessionRevocationReasonLogout,
			"",
		); errRevoke != nil {
			if errRevoke.Cause != nil {
				errRevoke.SetCause(fmt.Errorf("[SessionCtrl:LogoutAll]%w", errRevoke.Cause))
			}
			return errRevoke
		}

		// One entry for the request, not one per session. auth_logs carries no
		// session column, so the loop this replaces wrote rows that differed
		// only by id and timestamp -- and each one described the requesting
		// session anyway, never the session it had just ended. A user with a
		// dozen devices produced a dozen identical LogoutAll lines, which reads
		// in the admin history as a dozen separate events.
		//
		// Which sessions died, and why, is already recorded per session in
		// revoked_sessions.
		if errLog := c.authLogs.WithTxFromContext(tx).Create(tx, domain.NewAuthLog(session, domain.AuthLogStatusLogoutAll)); errLog != nil {
			return svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[SessionCtrl:LogoutAll]%w", errLog)),
			)
		}

		return nil
	})
}

// RevokeAllOnPasswordChange revokes every session of the user except the one that
// performed the change.
//
// It deliberately does not own a transaction. It runs on the caller's, through
// WithTxFromContext, so the revocation and the credential update commit together
// or not at all. Revoking after the commit instead would leave exactly the window
// this closes half-open: password rotated, stolen session still alive, one log
// line to show for it.
//
// Two things the caller therefore owes: an open transaction, and a cache clean
// map (cache.NewCleanMap) on the context — revokeAndCleanup writes to the
// revocation cache, and a rollback has to take those keys back out again.
//
// session.SessionID survives by design. Changing the password requires the
// current password, so a caller holding only a stolen token cannot reach this
// path at all, and logging out the client that just succeeded buys nothing.
//
// An empty SessionID spares nothing. Password recovery passes that: whoever
// answered the emailed code has no session yet, and the whole point of the reset
// is that somebody else's sessions should not survive it.
func (c SessionCtrl) RevokeAllOnPasswordChange(ctx context.Context, session domain.AuthenticatedSession) error {
	logger.LogCtx(ctx).Debugf(
		"[SessionCtrl:RevokeAllOnPasswordChange][userID:%d][keepSessionID:%s]",
		session.UserID,
		session.SessionID,
	)

	revoked, errRevoke := c.revokeAllSessions(ctx, session.UserID, domain.SessionRevocationReasonPasswordChange, session.SessionID)
	if errRevoke != nil {
		if errRevoke.Cause != nil {
			errRevoke.SetCause(fmt.Errorf("[SessionCtrl:RevokeAllOnPasswordChange]%w", errRevoke.Cause))
		}
		return errRevoke
	}

	if revoked == 0 {
		return nil
	}

	// One audit entry for the whole rotation rather than one per session: the
	// per-session record already exists in revoked_sessions, carrying the
	// password_change reason that says precisely why each one died.
	//
	// The status stays within the existing set. auth_logs.status is read by
	// admin-service as a backed PHP enum covering 1..5, so a sixth value would
	// not widen the vocabulary — it would break the page rendering any row that
	// carried it.
	if errLog := c.authLogs.WithTxFromContext(ctx).Create(ctx, domain.NewAuthLog(session, domain.AuthLogStatusLogoutAll)); errLog != nil {
		return svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[SessionCtrl:RevokeAllOnPasswordChange]%w", errLog)),
		)
	}

	return nil
}

// RefreshSession validates the provided refresh token and returns renewed session tokens.
func (c SessionCtrl) RefreshSession(ctx context.Context, in domain.SessionRefreshParams) (domain.SessionToken, error) {
	logger.LogCtx(ctx).Debugf("[SessionCtrl:RefreshSession][userID:%d][sessionID:%s]", in.AuthSession.UserID, in.AuthSession.SessionID)

	var err error
	ctx = c.transactionManager.Begin(ctx)
	ctx = cache.NewCleanMap(ctx)

	defer func() {
		if err != nil {
			logger.LogCtx(ctx).Debugf("[Rollback]%s", err)

			cache.CleanKeys(ctx)

			if rbErr := c.transactionManager.Rollback(ctx); rbErr != nil {
				logger.LogCtx(ctx).Errorf("[SessionCtrl:RefreshSession]%s", rbErr)
			}
		}
	}()

	presentedHash := c.sessionHelper.HashRefreshToken(in.RefreshToken)

	storedSession, errFind := c.sessions.WithTxFromContext(ctx).FindByUUIDForUpdate(ctx, in.AuthSession.SessionID)
	if errFind != nil {
		switch {
		case errors.Is(errFind, domain.ErrRecordNotFound):
			// The session is gone. If it was rotated away by an earlier refresh
			// and this same token opened it, the token has been used twice and
			// one of the two holders is not its owner.
			reused, errReuse := c.detectRefreshTokenReuse(ctx, in, presentedHash)
			if reused {
				// The sweep has to survive the error that reports it. Setting err
				// here would hand the deferred rollback the very revocations we
				// just made, so commit first and return without marking err --
				// the same shape the 2FA attempt counter uses when it persists a
				// failed check before rejecting it.
				if errCommit := c.transactionManager.Commit(ctx); errCommit != nil {
					err = svcErrors.New(
						appErrors.DatabaseError,
						appErrors.WithCause(fmt.Errorf("[SessionCtrl:RefreshSession][Commit]%w", errCommit)),
					)
					return domain.SessionToken{}, err
				}

				return domain.SessionToken{}, errReuse
			}
			if errReuse != nil {
				err = errReuse
				return domain.SessionToken{}, err
			}

			err = svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[SessionCtrl:RefreshSession]%w", errFind)),
			)
		case errors.Is(errFind, domain.ErrConcurrencyConflict):
			err = svcErrors.New(
				appErrors.ConcurrencyConflictError,
				appErrors.WithCause(fmt.Errorf("[SessionCtrl:RefreshSession]%w", errFind)),
			)
		default:
			err = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[SessionCtrl:RefreshSession]%w", errFind)),
			)
		}

		return domain.SessionToken{}, err
	}

	if storedSession.UserID != in.AuthSession.UserID {
		err = svcErrors.New(
			appErrors.AccessForbiddenError,
			appErrors.WithCause(fmt.Errorf("[SessionCtrl:RefreshSession][err: session not owned by user]")),
		)
		return domain.SessionToken{}, err
	}

	if subtle.ConstantTimeCompare([]byte(presentedHash), []byte(storedSession.RefreshTokenHash)) != 1 {
		err = svcErrors.New(
			svcErrors.UserSessionRefreshTokenInvalidError,
			appErrors.WithCause(fmt.Errorf("[SessionCtrl:RefreshSession][err: invalid refresh token]")),
		)
		return domain.SessionToken{}, err
	}
	if storedSession.RefreshExpireAt != nil && time.Now().UTC().After(*storedSession.RefreshExpireAt) {
		err = svcErrors.New(
			svcErrors.UserSessionRefreshTokenExpiredError,
			appErrors.WithCause(fmt.Errorf("[SessionCtrl:RefreshSession][err: refresh token expired]")),
		)
		return domain.SessionToken{}, err
	}

	if errRevoke := c.revokeAndCleanup(
		ctx,
		newRevokedSessionFromDB(storedSession, domain.SessionRevocationReasonRefresh),
	); errRevoke != nil {
		if errRevoke.Cause != nil {
			errRevoke.SetCause(fmt.Errorf("[SessionCtrl:RefreshSession]%w", errRevoke.Cause))
		}
		err = errRevoke
		return domain.SessionToken{}, err
	}

	refreshSessionIssueParams := &domain.SessionIssueParams{
		UserID:                  in.AuthSession.UserID,
		SessionClientDeviceData: in.SessionClientDeviceData,
		// The refreshed row continues the same login, so it keeps the original
		// sign-in time. Without this every rotation would reset created_at and
		// the session list would date a month-old login to the last refresh.
		SignedInAt: storedSession.CreatedAt,
	}

	storedAuthLog := &domain.AuthLog{
		UserID:                  refreshSessionIssueParams.UserID,
		SessionClientDeviceData: refreshSessionIssueParams.SessionClientDeviceData,
		Status:                  domain.AuthLogStatusSessionRefresh,
	}

	if dataGeo, errGeo := c.geoCtrl.GetGeoInfo(refreshSessionIssueParams.SessionClientDeviceData.IPAddress); errGeo == nil {
		refreshSessionIssueParams.SessionClientDeviceData.SetGeoInfo(dataGeo)
		storedAuthLog.City = dataGeo.City
		storedAuthLog.CountryName = dataGeo.CountryName
	} else {
		logger.LogCtx(ctx).Errorf("[SessionCtrl:RefreshSession]%s", errGeo)
	}

	if dataAnonymous, errAnonymous := c.geoCtrl.GetAnonymousInfo(refreshSessionIssueParams.SessionClientDeviceData.IPAddress); errAnonymous == nil {
		refreshSessionIssueParams.SessionClientDeviceData.SetAnonymousInfo(dataAnonymous)
		storedAuthLog.AnonymousInfo = dataAnonymous
	} else {
		logger.LogCtx(ctx).Errorf("[SessionCtrl:RefreshSession]%s", errAnonymous)
	}

	refreshedSession, errIssue := c.issueSession(ctx, refreshSessionIssueParams)
	if errIssue != nil {
		if errIssue.Cause != nil {
			errIssue.SetCause(fmt.Errorf("[SessionCtrl:RefreshSession]%w", errIssue.Cause))
		}
		err = errIssue
		return domain.SessionToken{}, err
	}

	if errAuth := c.authLogs.WithTxFromContext(ctx).Create(ctx, storedAuthLog); errAuth != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[SessionCtrl:RefreshSession]%w", errAuth)),
		)
		return domain.SessionToken{}, err
	}

	if cmErr := c.transactionManager.Commit(ctx); cmErr != nil {
		err = svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[SessionCtrl:RefreshSession][Commit]%w", cmErr)),
		)
		return domain.SessionToken{}, err
	}

	return refreshedSession, nil
}

// detectRefreshTokenReuse decides whether a refresh against a session that no
// longer exists is a replay of an already-rotated token, and revokes everything
// the user has if it is.
//
// Rotation deletes the session row and writes a revoked_sessions row carrying
// the hash it held. So a token presented after that point still has something
// to be compared against, and a match is not ambiguous: the token was accepted
// once already, the tokens it produced went to whoever refreshed first, and the
// party arriving second is holding a copy. Which of the two is the attacker
// cannot be known from here, so both lose their sessions and the real user
// signs in again.
//
// The comparison is what makes this safe to act on. Session ids travel in the
// access token, which users leave in logs and storage; acting on the id alone
// would let anyone holding a stale JWT sign a victim out at will. Requiring the
// matching token means only someone who actually holds it can trigger this.
//
// The bool reports whether reuse was found and acted on. It matters to the
// caller: a true means sessions were just revoked on its transaction and that
// work has to be committed, while an error with false is an infrastructure
// failure that should roll back. False with no error means "not reuse, carry
// on" — an unknown session, or one revoked before the hash column existed.
func (c SessionCtrl) detectRefreshTokenReuse(
	ctx context.Context,
	in domain.SessionRefreshParams,
	presentedHash string,
) (bool, *appErrors.ErrorResponse) {
	revoked, errFind := c.revokedSessions.WithTxFromContext(ctx).FindByUUID(ctx, in.AuthSession.SessionID)
	if errFind != nil {
		if errors.Is(errFind, domain.ErrRecordNotFound) {
			return false, nil
		}

		return false, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[detectRefreshTokenReuse]%w", errFind)),
		)
	}

	if revoked.RefreshTokenHash == "" ||
		subtle.ConstantTimeCompare([]byte(presentedHash), []byte(revoked.RefreshTokenHash)) != 1 {
		return false, nil
	}

	logger.LogCtx(ctx).Warnf(
		"[SessionCtrl:detectRefreshTokenReuse][msg: refresh token replayed after rotation; revoking every session for the user]"+
			"[userID:%d][sessionID:%s][revokedReason:%s]",
		revoked.UserID,
		in.AuthSession.SessionID,
		revoked.Reason,
	)

	swept, errRevoke := c.revokeAllSessions(ctx, revoked.UserID, domain.SessionRevocationReasonTokenReuse, "")
	if errRevoke != nil {
		if errRevoke.Cause != nil {
			errRevoke.SetCause(fmt.Errorf("[detectRefreshTokenReuse]%w", errRevoke.Cause))
		}
		return false, errRevoke
	}

	if swept > 0 {
		// Recorded against the device that presented the replayed token, which is
		// the one piece of attacker-adjacent context this flow actually has.
		auditLog := &domain.AuthLog{
			UserID:                  revoked.UserID,
			SessionClientDeviceData: in.SessionClientDeviceData,
			Status:                  domain.AuthLogStatusLogoutAll,
		}
		if errLog := c.authLogs.WithTxFromContext(ctx).Create(ctx, auditLog); errLog != nil {
			return false, svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[detectRefreshTokenReuse]%w", errLog)),
			)
		}
	}

	// The caller learns nothing beyond "this token is no good", which is all a
	// legitimate client needs and more than an attacker should get.
	return true, svcErrors.New(
		svcErrors.UserSessionRefreshTokenInvalidError,
		appErrors.WithCause(fmt.Errorf("[detectRefreshTokenReuse][err: refresh token reuse detected]")),
	)
}

// revokeAllSessions revokes every session the user has, optionally sparing one,
// on the transaction already open in ctx. It returns how many it revoked and
// leaves the audit entry to the caller, which knows the device context the
// sweep happened in.
func (c SessionCtrl) revokeAllSessions(
	ctx context.Context,
	userID domain.ID,
	reason domain.SessionRevocationReason,
	keep domain.SessionID,
) (int, *appErrors.ErrorResponse) {
	sessions, err := c.sessions.WithTxFromContext(ctx).ListByUserID(ctx, userID)
	if err != nil {
		return 0, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[revokeAllSessions]%w", err)),
		)
	}

	revoked := 0
	for _, stored := range sessions {
		if keep != "" && stored.UUID == keep {
			continue
		}

		if errRevoke := c.revokeAndCleanup(ctx, newRevokedSessionFromDB(stored, reason)); errRevoke != nil {
			if errRevoke.Cause != nil {
				errRevoke.SetCause(fmt.Errorf("[revokeAllSessions]%w", errRevoke.Cause))
			}
			return revoked, errRevoke
		}

		revoked++
	}

	return revoked, nil
}

// newRevokedSession creates a new RevokedSession for a successful logout.
func newRevokedSession(session domain.AuthenticatedSession, expAt *time.Time) *domain.RevokedSession {
	return &domain.RevokedSession{
		UUID:     session.SessionID,
		UserID:   session.UserID,
		Reason:   domain.SessionRevocationReasonLogout,
		ExpireAt: expAt,
	}
}

// newRevokedSessionFromDB creates a new RevokedSession from a Session.
func newRevokedSessionFromDB(session domain.Session, reason domain.SessionRevocationReason) *domain.RevokedSession {
	return &domain.RevokedSession{
		UUID:   session.UUID,
		UserID: session.UserID,
		Reason: reason,
		// Kept so a refresh token replayed after this point can still be
		// recognized as this session's — see detectRefreshTokenReuse.
		RefreshTokenHash: session.RefreshTokenHash,
		ExpireAt:         session.ExpireAt,
	}
}

// runTx wraps a function in a begin/commit/rollback block with safe error propagation.
func (c SessionCtrl) runTx(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	ctx = c.transactionManager.Begin(ctx)
	ctx = cache.NewCleanMap(ctx)

	defer func() {
		if err != nil {
			logger.LogCtx(ctx).Debugf("[Rollback]%s", err)

			cache.CleanKeys(ctx)

			if rbErr := c.transactionManager.Rollback(ctx); rbErr != nil {
				logger.LogCtx(ctx).Errorf("[Rollback]%s", rbErr)
			}
			return
		}

		// Commit on success
		if cmErr := c.transactionManager.Commit(ctx); cmErr != nil {
			err = svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[Commit]%w", cmErr)),
			)

			logger.LogCtx(ctx).Debugf("[Rollback]%s", err)
			cache.CleanKeys(ctx)

			if rbErr := c.transactionManager.Rollback(ctx); rbErr != nil {
				logger.LogCtx(ctx).Errorf("[Rollback]%s", rbErr)
			}
		}
	}()

	err = fn(ctx)
	return
}

// revokeAndCleanup does: create revoked record, delete session, log action, cache mark.
func (c SessionCtrl) revokeAndCleanup(
	ctx context.Context,
	revokedSession *domain.RevokedSession,
) *appErrors.ErrorResponse {
	if err := c.revokedSessions.WithTxFromContext(ctx).Create(ctx, revokedSession); err != nil {
		if !errors.Is(err, domain.ErrRecordExists) {
			return svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[revokeAndCleanup]%w", err)),
			)
		}
	}

	if err := c.sessions.WithTxFromContext(ctx).DeleteByUUID(ctx, revokedSession.UUID); err != nil {
		if !errors.Is(err, domain.ErrRecordNotFound) {
			return svcErrors.New(
				appErrors.DatabaseError,
				appErrors.WithCause(fmt.Errorf("[revokeAndCleanup]%w", err)),
			)
		}
	}

	if err := c.markRevoked(ctx, revokedSession.UUID, revokedSession.ExpireAt); err != nil {
		return svcErrors.New(
			appErrors.CacheError,
			appErrors.WithCause(fmt.Errorf("[revokeAndCleanup]%w", err)),
		)
	}

	return nil
}

// markRevoked marks the session as revoked in the cache with an optional TTL.
func (c SessionCtrl) markRevoked(ctx context.Context, sessionID domain.SessionID, expireAt *time.Time) error {
	var ttl time.Duration
	if expireAt != nil {
		ttl = expireAt.Sub(time.Now().UTC())
		if ttl < 0 {
			ttl = 0
		}
	}

	if err := c.revocationCache.UpdateWithTTL(ctx, sessionID.String(), domain.RevokedSession{}, ttl); err != nil {
		return fmt.Errorf("[markRevoked]%w", err)
	}

	return nil
}

// issueSession is an internal helper to create and persist a new session for the user.
func (c SessionCtrl) issueSession(ctx context.Context, sessionIssueParams *domain.SessionIssueParams) (domain.SessionToken, *appErrors.ErrorResponse) {
	logger.LogCtx(ctx).Debugf(
		"[SessionCtrl:issueSession][userID:%d][hasDeviceFingerprint:%t][hasIP:%t]",
		sessionIssueParams.UserID,
		sessionIssueParams.DeviceFingerprint != "",
		sessionIssueParams.IPAddress != "",
	)

	session, errIssue := c.sessionHelper.Issue(ctx, *sessionIssueParams)
	if errIssue != nil {
		return domain.SessionToken{}, svcErrors.New(
			appErrors.InternalServerError,
			appErrors.WithCause(fmt.Errorf("[issueSession]%w", errIssue)),
		)
	}

	storedSession := domain.Session{
		UUID:   session.SessionID,
		UserID: sessionIssueParams.UserID,
		// Zero on a fresh sign-in, which the repository reads as "stamp now".
		CreatedAt: sessionIssueParams.SignedInAt,
		// Only the hash is persisted. session.RefreshToken goes back to the
		// client in the response and is never written down anywhere.
		RefreshTokenHash:        c.sessionHelper.HashRefreshToken(session.RefreshToken),
		SessionClientDeviceData: sessionIssueParams.SessionClientDeviceData,
		AnonymousInfo:           sessionIssueParams.AnonymousInfo(),
	}

	if geoInfo := sessionIssueParams.GeoInfo(); geoInfo != nil {
		storedSession.City = geoInfo.City
		storedSession.CountryName = geoInfo.CountryName
	}

	if !session.AccessExpiresAt.IsZero() {
		expireAt := session.AccessExpiresAt
		storedSession.ExpireAt = &expireAt
	}

	if !session.RefreshExpiresAt.IsZero() {
		refreshExpireAt := session.RefreshExpiresAt
		storedSession.RefreshExpireAt = &refreshExpireAt
	}

	if err := c.sessions.WithTxFromContext(ctx).Create(ctx, &storedSession); err != nil {
		return domain.SessionToken{}, svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[issueSession]%w", err)),
		)
	}

	return session, nil
}

// revokeSessionByAdmin is an internal method for revoking a specific session identified by sessionID.
func (c SessionCtrl) revokeSessionByAdmin(ctx context.Context, sessionID domain.SessionID) *appErrors.ErrorResponse {
	logger.LogCtx(ctx).Debugf("[SessionCtrl:revokeSessionByAdmin][sessionID: %s]", sessionID)

	stored, err := c.sessions.WithTxFromContext(ctx).FindByUUID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, domain.ErrRecordNotFound) {
			return svcErrors.New(
				appErrors.RecordNotFoundError,
				appErrors.WithCause(fmt.Errorf("[revokeSessionByAdmin]%w", err)),
			)
		}
		return svcErrors.New(
			appErrors.DatabaseError,
			appErrors.WithCause(fmt.Errorf("[revokeSessionByAdmin]%w", err)),
		)
	}

	if errRevoke := c.revokeAndCleanup(ctx, newRevokedSessionFromDB(stored, domain.SessionRevocationReasonAdminKick)); errRevoke != nil {
		if errRevoke.Cause != nil {
			errRevoke.SetCause(fmt.Errorf("[revokeSessionByAdmin]%w", errRevoke.Cause))
		}
		return errRevoke
	}

	return nil
}
