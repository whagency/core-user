package app

import (
	"fmt"
	"io"

	"user-service/config"
	"user-service/internal/controllers"
	kycProviders "user-service/internal/controllers/kyc-providers"
	"user-service/internal/domain"
	"user-service/internal/infrastructure/db/postgres"
	"user-service/internal/infrastructure/security/passwords"
	"user-service/internal/infrastructure/security/sessions"
	outboxtransport "user-service/internal/transport/outbox"
	"user-service/services/geo"
	"user-service/services/kyc/amlbot"
	recaptchaV3 "user-service/services/recaptcha/v3"
	"user-service/tools"

	"github.com/dgraph-io/ristretto"
	"github.com/imroc/req/v3"
	"github.com/whagency/core-common/cache"
	"github.com/whagency/core-common/logger"
	"github.com/whagency/core-common/outbox"
	restrictionGRPC "github.com/whagency/core-common/services/restriction/grpc"
	restrictionService "github.com/whagency/core-common/services/restriction/http"
	"gorm.io/gorm"
)

type Core struct {
	UserCtrl             domain.UserController
	AuthCtrl             domain.AuthController
	PasswordRecoveryCtrl domain.PasswordRecoveryController
	SessionCtrl          domain.SessionController
	OTPCtrl              domain.OTPController
	TwoFactorCtrl        domain.TwoFactorController
	GeoCtrl              domain.GeoController
	UserEventCtrl        domain.UserEventController
	VerificationCtrl     domain.VerificationController

	// CleanupCtrl deletes rows the service has finished with. Driven by cron.
	CleanupCtrl *controllers.CleanupCtrl

	// OutboxWorker claims outbox messages and dispatches them to their handlers.
	// Driven by OutboxPool; not used directly.
	OutboxWorker *outbox.Worker

	// OutboxPool owns the outbox runtime: one relay goroutine claiming due
	// messages and N workers delivering them. Its Run loop is registered in the
	// errgroup in main.go so its lifecycle is bound to graceful shutdown.
	OutboxPool *outbox.Pool

	dbRepositories
	cacheRepositories
	securityComponents
	servicesHTTP
	servicesGRPC
}

type dbRepositories struct {
	Users              domain.UserRepository
	Contacts           domain.ContactRepository
	Profiles           domain.ProfileRepository
	Credentials        domain.CredentialRepository
	PasswordChangeLogs domain.PasswordChangeLogRepository
	Sessions           domain.SessionRepository
	RevokedSessions    domain.RevokedSessionRepository
	AuthLogs           domain.AuthLogRepository
	TwoFactorTokens    domain.TwoFactorTokenRepository
	TwoFactorSettings  domain.TwoFactorSettingsRepository
	Verifications      domain.VerificationRepository
	Outbox             domain.OutboxRepository
}

type cacheRepositories struct {
	RevokedSessions *cache.Repository[domain.RevokedSession]
}

type securityComponents struct {
	PasswordHelper domain.PasswordHelper
	SessionHelper  domain.SessionHelper
}

type servicesHTTP struct {
	Geo         domain.GeoService
	AmlBot      domain.AmlBotService
	Restriction domain.RestrictionService
	RecaptchaV3 *recaptchaV3.Service
}

type servicesGRPC struct {
	Restriction domain.RestrictionGRPCService
	closers     []io.Closer
}

// registerCloser registers an io.Closer to be closed when Core is closed.
func (s *servicesGRPC) registerCloser(c io.Closer) {
	s.closers = append(s.closers, c)
}

// Close closes all registered io.Closers in reverse order.
func (s *servicesGRPC) Close() error {
	var firstErr error
	for i := len(s.closers) - 1; i >= 0; i-- {
		if err := s.closers[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// CloseGRPC closes outgoing gRPC client connections owned by Core.
func (c *Core) CloseGRPC() error {
	return c.servicesGRPC.Close()
}

// buildCore initializes the core components of the application.
func (app *Application) buildCore() error {
	core := &Core{}

	// Initialize DB Repositories
	core.initDBRepositories(app.db)

	// Initialize Cache Repositories
	core.initCacheRepositories(app.globalLocalCache, app.remoteCacheManager)

	// Init Security Components
	if err := core.initSecurity(); err != nil {
		return fmt.Errorf("[buildCore]%w", err)
	}

	// Init Service Components
	if err := core.initServiceComponents(app.httpClient); err != nil {
		return fmt.Errorf("[buildCore]%w", err)
	}

	// Initialize Controllers
	if err := core.initControllers(app.DBTransactionManager(), app.QueueManager()); err != nil {
		return fmt.Errorf("[buildCore]%w", err)
	}

	app.core = core

	return nil
}

// initDBRepositories initializes the database repositories for the core components.
func (c *Core) initDBRepositories(db *gorm.DB) {
	c.dbRepositories.Users = postgres.NewUserRepository(db)
	c.dbRepositories.Contacts = postgres.NewContactRepository(db)
	c.dbRepositories.Profiles = postgres.NewProfileRepository(db)
	c.dbRepositories.Credentials = postgres.NewCredentialRepository(db)
	c.dbRepositories.PasswordChangeLogs = postgres.NewPasswordChangeLogRepository(db)
	c.dbRepositories.Sessions = postgres.NewSessionRepository(db)
	c.dbRepositories.RevokedSessions = postgres.NewRevokedSessionRepository(db)
	c.dbRepositories.AuthLogs = postgres.NewAuthLogRepository(db)
	c.dbRepositories.TwoFactorTokens = postgres.NewTwoFactorTokenRepository(db)
	c.dbRepositories.TwoFactorSettings = postgres.NewTwoFactorSettingsRepository(db)
	c.dbRepositories.Verifications = postgres.NewVerificationRepository(db)
	c.dbRepositories.Outbox = postgres.NewOutboxRepository(db)
}

// initCacheRepositories initializes the cache repositories for the core components.
func (c *Core) initCacheRepositories(globalLocalCache *ristretto.Cache, remoteCacheManager cache.RemoteCacheManager) {
	var err error

	c.cacheRepositories.RevokedSessions, err = cache.New[domain.RevokedSession](
		cache.RepoOptions{
			Options:          domain.CacheKeys[domain.RevokedSessionCacheKeyID].Options,
			Name:             domain.CacheKeys[domain.RevokedSessionCacheKeyID].Name,
			CacheLocalGlobal: globalLocalCache,
			RemoteCache:      remoteCacheManager,
		},
	)
	if err != nil {
		logger.Log().Fatalf("[Application][Core:initCacheRepositories]%s", err)
	}
}

// initServiceComponents initializes the services for the core components.
func (c *Core) initServiceComponents(httpClient *req.Client) error {
	var err error

	// HTTP services

	c.servicesHTTP.Geo, err = geo.GetGeoService()
	if err != nil {
		return fmt.Errorf("[initServiceComponents]%w", err)
	}

	c.servicesHTTP.AmlBot = amlbot.NewAmlBotService(httpClient)

	c.servicesHTTP.RecaptchaV3 = recaptchaV3.NewRecaptchaV3Service(httpClient)

	c.servicesHTTP.Restriction = restrictionService.NewRestrictionService(httpClient, config.Commons().RestrictionServiceURL, config.Commons().SecurityToken)

	// gRPC services

	c.servicesGRPC.Restriction = restrictionGRPC.NewRestrictionService(
		config.Commons().RestrictionServiceGrpcURL,
		restrictionGRPC.WithInsecureTransport(),
		restrictionGRPC.WithTimeoutExtCall(config.Commons().GrpcTimeout),
	)
	c.servicesGRPC.registerCloser(c.servicesGRPC.Restriction)

	return nil
}

// initControllers initializes the controllers for the core components.
func (c *Core) initControllers(dbTransactionManager domain.TransactionManager, queueManager domain.QueueManager) error {
	otpPublisher, err := queueManager.GetPublisher(domain.OTPQueuePublisherType)
	if err != nil {
		return fmt.Errorf("[initControllers]%w", err)
	}

	c.OTPCtrl, err = controllers.NewOTPController(
		otpPublisher,
		config.Commons().OTPSecretPepperBytes,
		func() []controllers.OTPOption {
			if config.Commons().OTPFixedCode == "" {
				return nil
			}

			return []controllers.OTPOption{
				controllers.WithFixedOTPCode(config.Commons().OTPFixedCode),
			}
		}()...,
	)
	if err != nil {
		return fmt.Errorf("[initControllers]%w", err)
	}

	c.GeoCtrl = controllers.NewGeoController(
		c.servicesHTTP.Geo,
	)

	userEventPublisher, err := queueManager.GetPublisher(domain.UserLifecycleQueuePublisherType)
	if err != nil {
		return fmt.Errorf("[initControllers]%w", err)
	}

	c.UserEventCtrl = controllers.NewUserEventController(
		userEventPublisher,
	)

	c.CleanupCtrl = controllers.NewCleanupController(
		c.dbRepositories.Sessions,
		c.dbRepositories.RevokedSessions,
		c.dbRepositories.TwoFactorTokens,
		controllers.CleanupRetention{
			Sessions:        config.Cron().Cleanup.SessionRetention,
			RevokedSessions: config.Cron().Cleanup.RevokedSessionRetention,
			TwoFactorTokens: config.Cron().Cleanup.TwoFactorTokenRetention,
		},
	)

	c.SessionCtrl = controllers.NewSessionController(
		c.GeoCtrl,
		c.dbRepositories.Sessions,
		c.dbRepositories.RevokedSessions,
		c.dbRepositories.AuthLogs,
		c.cacheRepositories.RevokedSessions,
		c.securityComponents.SessionHelper,
		dbTransactionManager,
	)

	c.UserCtrl = controllers.NewUserController(
		c.dbRepositories.Users,
		c.dbRepositories.Contacts,
		c.dbRepositories.Profiles,
		c.dbRepositories.Credentials,
		c.dbRepositories.PasswordChangeLogs,
		c.dbRepositories.TwoFactorTokens,
		c.dbRepositories.Verifications,
		c.OTPCtrl,
		c.dbRepositories.Outbox,
		c.UserEventCtrl,
		c.SessionCtrl,
		c.GeoCtrl,
		c.securityComponents.PasswordHelper,
		c.servicesGRPC.Restriction,
		dbTransactionManager,
		c.servicesHTTP.RecaptchaV3,
	)

	c.TwoFactorCtrl = controllers.NewTwoFactorController(
		c.dbRepositories.TwoFactorTokens,
		c.dbRepositories.TwoFactorSettings,
		c.dbRepositories.Users,
		c.dbRepositories.Contacts,
		c.OTPCtrl,
		dbTransactionManager,
	)

	c.AuthCtrl = controllers.NewAuthController(
		c.dbRepositories.Users,
		c.dbRepositories.Contacts,
		c.dbRepositories.Profiles,
		c.dbRepositories.Credentials,
		c.dbRepositories.PasswordChangeLogs,
		c.dbRepositories.Verifications,
		c.dbRepositories.Sessions,
		c.dbRepositories.AuthLogs,
		c.securityComponents.PasswordHelper,
		c.TwoFactorCtrl,
		c.GeoCtrl,
		c.SessionCtrl,
		dbTransactionManager,
		c.servicesHTTP.RecaptchaV3,
	)

	// Verification providers
	verificationProviders := map[domain.VerificationProvider]domain.VerificationProviderController{
		domain.VerificationProvidersAmlBot: kycProviders.NewAmlBotController(c.servicesHTTP.AmlBot),
	}

	// Build the outbox handler registry and worker. Both handlers are pure
	// transport: they republish the lifecycle event onto the same queue publisher
	// the controllers used to call directly.
	outboxRegistry := outbox.NewRegistry()
	outboxRegistry.Register(outboxtransport.NewUserCreatedHandler(c.UserEventCtrl))
	outboxRegistry.Register(outboxtransport.NewUserVerifyLevelUpdatedHandler(c.UserEventCtrl))

	outboxSettings := config.Cron().Outbox
	c.OutboxWorker = outbox.NewWorker(
		c.dbRepositories.Outbox,
		outboxRegistry,
		outboxSettings.WorkerConfig(tools.OutboxHooks()),
	)
	c.OutboxPool = outbox.NewPool(c.OutboxWorker, outboxSettings.PoolConfig())

	c.VerificationCtrl = controllers.NewVerificationController(
		verificationProviders,
		c.UserEventCtrl,
		c.dbRepositories.Outbox,
		c.dbRepositories.Verifications,
		c.dbRepositories.Users,
		dbTransactionManager,
		c.UserCtrl,
	)

	c.PasswordRecoveryCtrl, err = controllers.NewPasswordRecoveryController(
		c.dbRepositories.Users,
		c.dbRepositories.Contacts,
		c.dbRepositories.Credentials,
		c.dbRepositories.PasswordChangeLogs,
		c.dbRepositories.TwoFactorTokens,
		c.OTPCtrl,
		c.securityComponents.PasswordHelper,
		c.SessionCtrl,
		dbTransactionManager,
		c.servicesHTTP.RecaptchaV3,
	)
	if err != nil {
		return fmt.Errorf("[initControllers]%w", err)
	}

	return nil
}

// initSecurity initializes the security components for the core components.
func (c *Core) initSecurity() error {
	c.securityComponents.PasswordHelper = passwords.NewBcryptPasswordHelper()

	sessionHelper, err := sessions.NewJWTSessionHelper(
		config.Commons().JWTAccessSecretBytes,
		c.cacheRepositories.RevokedSessions,
		sessions.WithIssuer(config.Commons().AppName),
		sessions.WithAdditionalIssuers(config.Commons().JWTAdditionalIssuers...),
	)
	if err != nil {
		return fmt.Errorf("[initSecurity]%w", err)
	}
	c.securityComponents.SessionHelper = sessionHelper

	return nil
}
