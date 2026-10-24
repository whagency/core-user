package app

import (
	"net/http"
	"time"

	"user-service/config"
	authHandlers "user-service/internal/transport/http/handlers/auth"
	sessionHandlers "user-service/internal/transport/http/handlers/sessions"
	internalHandlers "user-service/internal/transport/http/handlers/sessions/internals"
	twoFaHandlers "user-service/internal/transport/http/handlers/two_fa"
	twoFaProtectedHandlers "user-service/internal/transport/http/handlers/two_fa/protected"
	usersHandlers "user-service/internal/transport/http/handlers/users"
	"user-service/internal/transport/http/handlers/users/internals"
	usersProtectedHandlers "user-service/internal/transport/http/handlers/users/protected"
	verificationsProtectedHandlers "user-service/internal/transport/http/handlers/verifications/protected"
	verificationsWebhookHandlers "user-service/internal/transport/http/handlers/verifications/webhooks"
	"user-service/internal/transport/http/middleware"
	"user-service/tools"

	"github.com/gin-gonic/gin"
	httpCommonHandlers "github.com/whagency/core-common/http/handler"
	httpMiddleware "github.com/whagency/core-common/http/middleware"
	"github.com/whagency/core-common/logger"
	"github.com/whagency/core-common/ratelimit"
	"golang.org/x/time/rate"
)

// setupHTTPServer sets up the server
//
//	@title User Service
//	@version 1.0.0
//	@description ### 📘 User Service API
//	@description Provides identity, authentication, profile management, session lifecycle, two-factor authentication, password recovery, and KYC verification orchestration.
//	@description ### 🔑 Authentication
//	@description Some endpoints require an **Authorization** header:
//	@description
//	@description ```http
//	@description Authorization: Bearer <token>
//	@description ```
//	@host https://api.app-stage.pro
//	@BasePath /user/
func (app *Application) setupHTTPServer() error {
	logger.Log().Info("[Application:setupHTTPServer][msg: setting up server]")

	if config.Commons().IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	// Handlers

	userRegisterHandler := usersHandlers.NewUserRegisterHandler(app.Core().UserCtrl)
	verifyContactHandler := usersHandlers.NewVerifyContactHandler(app.Core().UserCtrl)
	passwordForgotHandler := usersHandlers.NewPasswordForgotHandler(app.Core().PasswordRecoveryCtrl)
	passwordResetConfirmHandler := usersHandlers.NewPasswordResetConfirmHandler(app.Core().PasswordRecoveryCtrl)
	updateProfileHandler := usersProtectedHandlers.NewUpdateProfileHandler(app.Core().UserCtrl)
	getProfileHandler := usersProtectedHandlers.NewGetProfileHandler(app.Core().UserCtrl)
	passwordChangeHandler := usersProtectedHandlers.NewPasswordChangeHandler(app.Core().UserCtrl)

	otpChallengeResendHandler := twoFaHandlers.NewChallengeResendHandler(app.Core().TwoFactorCtrl)

	twoFactorActivateHandler := twoFaProtectedHandlers.NewTwoFactorActivateHandler(app.Core().TwoFactorCtrl)
	twoFactorConfirmHandler := twoFaProtectedHandlers.NewTwoFactorConfirmHandler(app.Core().TwoFactorCtrl)
	twoFactorDeactivateHandler := twoFaProtectedHandlers.NewTwoFactorDeactivateHandler(app.Core().TwoFactorCtrl)
	twoFactorSettingsHandler := twoFaProtectedHandlers.NewTwoFactorSettingsHandler(app.Core().TwoFactorCtrl)
	twoFactorChallengeResendHandler := twoFaProtectedHandlers.NewChallengeResendHandler(app.Core().TwoFactorCtrl)

	loginHandler := authHandlers.NewLoginHandler(app.Core().AuthCtrl)
	loginChallengeConfirmHandler := authHandlers.NewLoginChallengeConfirmHandler(app.Core().AuthCtrl)
	meHandler := authHandlers.NewMeHandler(app.Core().AuthCtrl)
	logoutHandler := authHandlers.NewLogoutHandler(app.Core().SessionCtrl)
	logoutAllHandler := authHandlers.NewLogoutAllHandler(app.Core().SessionCtrl)
	activeSessionsHandler := sessionHandlers.NewActiveSessionsHandler(app.Core().SessionCtrl)
	deleteSessionHandler := sessionHandlers.NewDeleteSessionHandler(app.Core().SessionCtrl)
	refreshSessionHandler := sessionHandlers.NewRefreshSessionHandler(app.Core().SessionCtrl)

	verificationInitHandler := verificationsProtectedHandlers.NewVerificationInitHandler(app.Core().VerificationCtrl)

	// Webhook handlers
	amlBotWebhookHandler := verificationsWebhookHandlers.NewAmlBotWebhookHandler(app.Core().VerificationCtrl)

	// Internal handlers
	deleteSessionByAdminHandler := internalHandlers.NewDeleteSessionByAdminHandler(app.Core().SessionCtrl)
	validateSessionHandler := internalHandlers.NewValidateSessionHandler(app.Core().SessionHelper, app.Core().UserCtrl)
	blockUserHandler := internals.NewBlockUserHandler(app.Core().UserCtrl)
	registerEventHandler := internals.NewRegisterEventHandler(app.Core().UserEventCtrl)

	router := gin.New()
	router.Use(
		gin.Recovery(),
		httpMiddleware.GinObservabilityMiddleware(),
		httpMiddleware.CORS(),
	)
	router.NoRoute(httpCommonHandlers.RouteNotFound)

	// Adding Metrics
	tools.LinkToPrometheusToGin(router)

	// API v1
	v1 := router.Group("api/v1")

	// Public endpoints

	// Note: limiters are per-endpoint to allow different policies for each route.
	limiters := newPublicLimiters()

	// User endpoints
	userPublic := v1.Group("/users")
	userPublic.POST("/register", httpMiddleware.GinRateLimitMiddleware(limiters.register, httpMiddleware.GetClientIP), userRegisterHandler.Handle)
	userPublic.POST("/verify-contact", httpMiddleware.GinRateLimitMiddleware(limiters.verifyContact, httpMiddleware.GetClientIP), verifyContactHandler.Handle)
	userPublic.POST("/password/forgot", httpMiddleware.GinRateLimitMiddleware(limiters.passwordForgot, httpMiddleware.GetClientIP), passwordForgotHandler.Handle)
	userPublic.POST("/password/reset/confirm", httpMiddleware.GinRateLimitMiddleware(limiters.passwordResetConfirm, httpMiddleware.GetClientIP), passwordResetConfirmHandler.Handle)

	userProtected := v1.Group("/users")
	userProtected.Use(middleware.ValidateUserSession(app.Core().SessionHelper, middleware.ValidateSessionOptions{}))
	userProtected.GET("/get-profile", getProfileHandler.Handle)
	userProtected.PATCH("/update-profile", updateProfileHandler.Handle)
	userProtected.POST("/password-change", passwordChangeHandler.Handle)

	twoFAPublic := v1.Group("/2fa")
	twoFAPublic.POST("/otp/resend", httpMiddleware.GinRateLimitMiddleware(limiters.otpResend, httpMiddleware.GetClientIP), otpChallengeResendHandler.Handle)

	twoFAProtected := v1.Group("/2fa")
	twoFAProtected.Use(middleware.ValidateUserSession(app.Core().SessionHelper, middleware.ValidateSessionOptions{}))
	twoFAProtected.POST("/activate", twoFactorActivateHandler.Handle)
	twoFAProtected.POST("/deactivate", twoFactorDeactivateHandler.Handle)
	twoFAProtected.POST("/confirm", twoFactorConfirmHandler.Handle)
	twoFAProtected.GET("/settings", twoFactorSettingsHandler.Handle)
	twoFAProtected.POST("/challenge/resend", twoFactorChallengeResendHandler.Handle)

	authPublic := v1.Group("/auth")
	authPublic.POST("/login", httpMiddleware.GinRateLimitMiddleware(limiters.login, httpMiddleware.GetClientIP), loginHandler.Handle)
	authPublic.POST("/login/challenge/confirm", httpMiddleware.GinRateLimitMiddleware(limiters.loginConfirm, httpMiddleware.GetClientIP), loginChallengeConfirmHandler.Handle)

	authProtected := v1.Group("/auth")
	authProtected.Use(middleware.ValidateUserSession(app.Core().SessionHelper, middleware.ValidateSessionOptions{}))
	authProtected.GET("/me", meHandler.Handle)
	authProtected.POST("/logout", logoutHandler.Handle)
	authProtected.POST("/logout-all", logoutAllHandler.Handle)
	authProtected.GET("/sessions", activeSessionsHandler.Handle)
	authProtected.DELETE("/sessions/:sessionId", deleteSessionHandler.Handle)

	authRefresh := v1.Group("/auth")
	authRefresh.Use(middleware.ValidateUserSessionForRefresh(app.Core().SessionHelper))
	authRefresh.POST("/sessions/refresh", refreshSessionHandler.Handle)

	// Verification endpoints
	verificationsProtected := v1.Group("/verifications")
	verificationsProtected.Use(middleware.ValidateUserSession(app.Core().SessionHelper, middleware.ValidateSessionOptions{}))
	verificationsProtected.POST("/init", verificationInitHandler.Handle)

	// Webhooks
	verificationsPublic := v1.Group("/verifications")
	verificationsPublic.POST("/aml-bot/webhook", amlBotWebhookHandler.Handle)

	// Internal endpoints
	internalEndpoints := v1.Group("/internal")
	internalEndpoints.Use(httpMiddleware.ValidateSecurityToken(
		config.Commons().SecurityToken,
		config.Commons().SecurityTokenHeader,
	))
	internalEndpoints.DELETE("/sessions/:sessionId", deleteSessionByAdminHandler.Handle)
	internalEndpoints.POST("/sessions/validate", validateSessionHandler.Handle)
	internalEndpoints.POST("/users/block", blockUserHandler.Handle)
	internalEndpoints.POST("/users/events", registerEventHandler.Handle)

	v1.GET("/health", httpCommonHandlers.HealthCheck)

	app.httpServer = &http.Server{
		Addr:              ":" + config.HTTP().Port,
		Handler:           router,
		ReadTimeout:       config.HTTP().ReadTimeout,
		ReadHeaderTimeout: config.HTTP().ReadHeaderTimeout,
		WriteTimeout:      config.HTTP().WriteTimeout,
		MaxHeaderBytes:    http.DefaultMaxHeaderBytes,
	}

	return nil
}

// publicLimiters holds the rate limiters for public endpoints to prevent abuse while allowing legitimate use.
type publicLimiters struct {
	register             *ratelimit.LimiterStore
	verifyContact        *ratelimit.LimiterStore
	passwordForgot       *ratelimit.LimiterStore
	passwordResetConfirm *ratelimit.LimiterStore
	login                *ratelimit.LimiterStore
	loginConfirm         *ratelimit.LimiterStore
	otpResend            *ratelimit.LimiterStore
}

// newPublicLimiters initializes the rate limiters for public endpoints with appropriate limits to prevent abuse while allowing legitimate use.
func newPublicLimiters() publicLimiters {
	cfg := config.HTTP()

	return publicLimiters{
		register: newRateLimiter(
			cfg.UserRegisterRateLimitRPS,
			cfg.UserRegisterRateLimitBurst,
			cfg.UserRegisterRateLimitTTL,
		),
		verifyContact: newRateLimiter(
			cfg.UserVerifyContactRateLimitRPS,
			cfg.UserVerifyContactRateLimitBurst,
			cfg.UserVerifyContactRateLimitTTL,
		),
		passwordForgot: newRateLimiter(
			cfg.UserPasswordForgotRateLimitRPS,
			cfg.UserPasswordForgotRateLimitBurst,
			cfg.UserPasswordForgotRateLimitTTL,
		),
		passwordResetConfirm: newRateLimiter(
			cfg.UserPasswordResetRateLimitRPS,
			cfg.UserPasswordResetRateLimitBurst,
			cfg.UserPasswordResetRateLimitTTL,
		),
		login: newRateLimiter(
			cfg.UserLoginRateLimitRPS,
			cfg.UserLoginRateLimitBurst,
			cfg.UserLoginRateLimitTTL,
		),
		loginConfirm: newRateLimiter(
			cfg.UserLoginConfirmRateLimitRPS,
			cfg.UserLoginConfirmRateLimitBurst,
			cfg.UserLoginConfirmRateLimitTTL,
		),
		otpResend: newRateLimiter(
			cfg.UserTwoFAOTPResendRateLimitRPS,
			cfg.UserTwoFAOTPResendRateLimitBurst,
			cfg.UserTwoFAOTPResendRateLimitTTL,
		),
	}
}

// newRateLimiter creates a new rate limiter with the specified rate limit parameters.
func newRateLimiter(rps float64, burst int, ttl time.Duration) *ratelimit.LimiterStore {
	return ratelimit.NewLimiterStore(ratelimit.LimiterConfig{
		RPS:   rate.Limit(rps),
		Burst: burst,
		TTL:   ttl,
	})
}
