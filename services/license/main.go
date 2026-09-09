// Command license-service is ClaudePass's hosted license service (ADR-0006,
// CLA-15): it runs Stripe Checkout for the $9.99/month plan, listens for
// Stripe webhooks, and issues or refuses Ed25519-signed license tokens that
// the cpass binary verifies entirely offline (internal/license). See
// services/license/README.md for the environment variables and the deploy
// runbook.
package main

import (
	"log/slog"
	"net/http"
	"os"

	"claudepass/services/license/internal/config"
	"claudepass/services/license/internal/mailer"
	"claudepass/services/license/internal/server"
	"claudepass/services/license/internal/store"
	"claudepass/services/license/internal/stripeapi"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "error", err)
		os.Exit(1)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Error("open store", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	stripeClient := stripeapi.New(cfg.StripeSecretKey, cfg.StripePriceID, cfg.BaseURL)

	var mail mailer.Mailer = mailer.NoopMailer{}
	if cfg.MailerConfigured() {
		mail = mailer.SMTPMailer{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword,
			From:     cfg.SMTPFrom,
		}
	} else {
		log.Warn("SMTP is not configured; POST /reissue will refuse every request")
	}

	srv := server.New(server.Deps{
		Store:         st,
		Checkout:      stripeClient,
		Portal:        stripeClient,
		Mailer:        mail,
		SigningKey:    cfg.SigningKey,
		WebhookSecret: cfg.StripeWebhookSecret,
		BaseURL:       cfg.BaseURL,
		Logger:        log,
	})

	log.Info("license service listening", "addr", cfg.Addr, "base_url", cfg.BaseURL)
	if err := http.ListenAndServe(cfg.Addr, srv.Handler()); err != nil {
		log.Error("serve", "error", err)
		os.Exit(1)
	}
}
