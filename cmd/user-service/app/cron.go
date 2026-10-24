package app

import (
	"fmt"

	"user-service/config"
	"user-service/tools"

	"github.com/whagency/core-common/cron"
	outboxcron "github.com/whagency/core-common/outbox/cronjobs"
)

// CleanupJobName is the retention sweep, exported so alert rules and runbooks
// can name it without re-deriving the string.
const CleanupJobName = "user.cleanup"

// setupCronManager registers the maintenance cron jobs.
//
// The manager started out existing only so the outbox had somewhere to hang its
// prune and lag jobs. It now also carries the retention sweep for the tables
// this service grows on its own -- sessions, revoked sessions and two-factor
// tokens -- which had no cleanup at all.
func (app *Application) setupCronManager() error {
	app.cronManager = cron.NewManager()

	if err := app.cronManager.AddFunc(
		config.Cron().Cleanup.Spec,
		CleanupJobName,
		app.Core().CleanupCtrl.Run,
	); err != nil {
		return fmt.Errorf("[setupCronManager]%w", err)
	}

	if err := outboxcron.Register(
		app.cronManager,
		app.Core().Outbox,
		config.Cron().Outbox,
		tools.SetOutboxLag,
	); err != nil {
		return fmt.Errorf("[setupCronManager]%w", err)
	}

	return nil
}
