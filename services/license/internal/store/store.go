// Package store is the license service's SQLite-backed state: which
// Stripe customer maps to which email and subscription status, and the
// one-time-show token for each Checkout Session. No license token is ever
// logged from here; a token passes through as a plain string value and the
// package never writes one to a log, only to the columns documented below.
//
// SQLite via modernc.org/sqlite (a pure-Go driver, CGo-free) rather than
// Cloudflare D1: this service deploys as a single Fly.io machine with a
// persistent volume, not a Cloudflare Worker. See services/license/README.md.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

// Status values for the customers table.
const (
	StatusActive   = "active"
	StatusCanceled = "canceled"
)

// Store wraps the SQLite connection and the license service's schema.
type Store struct {
	db *sql.DB
}

// Open opens (creating if absent) the SQLite database at path and applies
// the schema. Callers must Close it.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// SQLite allows exactly one writer; the license service's write volume
	// (checkout/webhook/reissue events) is low enough that serializing
	// through a single connection is simpler and safer than WAL tuning.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close() // best-effort: the migration error above is what we report
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS customers (
	customer_id     TEXT PRIMARY KEY,
	email           TEXT NOT NULL,
	subscription_id TEXT NOT NULL DEFAULT '',
	status          TEXT NOT NULL DEFAULT 'active',
	period_end      INTEGER NOT NULL DEFAULT 0,
	updated_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS customers_email_idx ON customers(email);

CREATE TABLE IF NOT EXISTS checkout_tokens (
	session_id  TEXT PRIMARY KEY,
	customer_id TEXT NOT NULL,
	token       TEXT,
	shown       INTEGER NOT NULL DEFAULT 0,
	created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS processed_events (
	event_id     TEXT PRIMARY KEY,
	processed_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS issued_tokens (
	jti         TEXT PRIMARY KEY,
	customer_id TEXT NOT NULL,
	issued_at   INTEGER NOT NULL,
	exp         INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS issued_tokens_customer_idx ON issued_tokens(customer_id);
`
	_, err := s.db.Exec(schema)
	return err
}

// ErrAlreadyProcessed is returned by IssueForCheckout and UpdateSubscription
// when eventID was already handled by a prior delivery — the caller should
// treat the webhook delivery as a no-op success (Stripe retries
// deliveries, so this must be idempotent) rather than an error.
var ErrAlreadyProcessed = errors.New("store: event already processed")

// markEventProcessed records eventID as handled, within the caller's
// transaction. It returns ErrAlreadyProcessed without failing the
// transaction — the caller decides whether that means "roll back and
// report a no-op" (the normal case) or something else.
func markEventProcessed(ctx context.Context, tx *sql.Tx, eventID string, now int64) error {
	res, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO processed_events(event_id, processed_at) VALUES(?, ?)`,
		eventID, now)
	if err != nil {
		return fmt.Errorf("store: mark event processed: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: mark event processed: %w", err)
	}
	if n == 0 {
		return ErrAlreadyProcessed
	}
	return nil
}

// IssuedToken bundles IssueForCheckout's inputs: a checkout.session.completed
// event's identifying fields plus the token just minted for it. It's a
// struct rather than nine positional parameters because callers (and this
// method's own tests) read more clearly naming each field once.
type IssuedToken struct {
	EventID    string
	SessionID  string
	CustomerID string
	Email      string
	PeriodEnd  int64 // 0 if not yet known
	Now        int64
	Token      string // the full signed token; cleared from checkout_tokens once shown
	JTI        string // retained in issued_tokens even after Token is cleared
	Exp        int64
}

// IssueForCheckout applies a checkout.session.completed event: it records
// eventID as processed and writes the new token, its customer->jti record,
// and the customer row, all in one transaction. Recording "processed" and
// applying the effect commit or fail together on purpose — marking an
// event processed before its write lands would mean a transient failure (a
// locked database, say) silently swallows Stripe's retry forever, having
// issued no token. A second delivery of the same eventID returns
// ErrAlreadyProcessed and writes nothing; the caller replies 200 either
// way.
func (s *Store) IssueForCheckout(ctx context.Context, it IssuedToken) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: issue for checkout: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op once Commit succeeds (sql.ErrTxDone); the standard defer-Rollback idiom

	if err := markEventProcessed(ctx, tx, it.EventID, it.Now); err != nil {
		return err // ErrAlreadyProcessed or a real error; either way, nothing to commit
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO customers(customer_id, email, status, period_end, updated_at)
VALUES(?, ?, ?, ?, ?)
ON CONFLICT(customer_id) DO UPDATE SET
	email = excluded.email,
	status = excluded.status,
	period_end = excluded.period_end,
	updated_at = excluded.updated_at
`, it.CustomerID, it.Email, StatusActive, it.PeriodEnd, it.Now); err != nil {
		return fmt.Errorf("store: issue for checkout: upsert customer: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO checkout_tokens(session_id, customer_id, token, shown, created_at)
VALUES(?, ?, ?, 0, ?)
ON CONFLICT(session_id) DO UPDATE SET
	token = excluded.token,
	shown = 0,
	created_at = excluded.created_at
`, it.SessionID, it.CustomerID, it.Token, it.Now); err != nil {
		return fmt.Errorf("store: issue for checkout: save token: %w", err)
	}

	if err := recordIssuedToken(ctx, tx, it.JTI, it.CustomerID, it.Now, it.Exp); err != nil {
		return fmt.Errorf("store: issue for checkout: %w", err)
	}

	return tx.Commit()
}

// recordIssuedToken inserts the customer->jti audit row within the
// caller's transaction.
func recordIssuedToken(ctx context.Context, tx *sql.Tx, jti, customerID string, issuedAt, exp int64) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO issued_tokens(jti, customer_id, issued_at, exp) VALUES(?, ?, ?, ?)`,
		jti, customerID, issuedAt, exp)
	return err
}

// RecordIssuedToken records the customer->jti audit row for a token minted
// outside the checkout flow — POST /reissue's fresh token. It is
// deliberately its own small transaction rather than sharing one with the
// email send: which jti was minted is worth keeping even if the email
// delivery that follows fails and the caller reports an error.
func (s *Store) RecordIssuedToken(ctx context.Context, jti, customerID string, issuedAt, exp int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: record issued token: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op once Commit succeeds (sql.ErrTxDone); the standard defer-Rollback idiom
	if err := recordIssuedToken(ctx, tx, jti, customerID, issuedAt, exp); err != nil {
		return fmt.Errorf("store: record issued token: %w", err)
	}
	return tx.Commit()
}

// ErrTokenNotFound is returned by TakeCheckoutToken when the session is
// unknown — the webhook for it has not (yet) been processed.
var ErrTokenNotFound = errors.New("store: checkout session not found")

// ErrTokenAlreadyShown is returned by TakeCheckoutToken on a second call
// for the same session: the token was already displayed once and is no
// longer readable from the store, by design (GET /license shows it once).
var ErrTokenAlreadyShown = errors.New("store: token already shown")

// TakeCheckoutToken returns the token issued for sessionID and clears it
// from the store in the same statement, so it can never be displayed
// twice — even to two concurrent requests for the same session_id, only
// one wins the UPDATE and gets the token back.
func (s *Store) TakeCheckoutToken(ctx context.Context, sessionID string) (string, error) {
	var token sql.NullString
	var shown int
	err := s.db.QueryRowContext(ctx,
		`SELECT token, shown FROM checkout_tokens WHERE session_id = ?`, sessionID,
	).Scan(&token, &shown)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrTokenNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: take checkout token: %w", err)
	}
	if shown == 1 || !token.Valid {
		return "", ErrTokenAlreadyShown
	}

	res, err := s.db.ExecContext(ctx,
		`UPDATE checkout_tokens SET token = NULL, shown = 1 WHERE session_id = ? AND shown = 0`,
		sessionID)
	if err != nil {
		return "", fmt.Errorf("store: take checkout token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("store: take checkout token: %w", err)
	}
	if n == 0 {
		// Lost the race to a concurrent request that took it first.
		return "", ErrTokenAlreadyShown
	}
	return token.String, nil
}

// UpdateSubscription applies a customer.subscription.updated or .deleted
// event: the new status and, when known, the subscription's current period
// end. It upserts a row if the customer is not yet known (e.g. a
// subscription event arriving before the checkout.session.completed event
// that would normally create the row) so status is never lost, though
// email stays blank until a checkout event fills it in. Like
// IssueForCheckout, recording eventID as processed and applying the write
// happen in one transaction, so a failed write is retried by Stripe's next
// delivery instead of being silently marked done.
func (s *Store) UpdateSubscription(ctx context.Context, eventID, customerID, subscriptionID, status string, periodEnd, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: update subscription: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op once Commit succeeds (sql.ErrTxDone); the standard defer-Rollback idiom

	if err := markEventProcessed(ctx, tx, eventID, now); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO customers(customer_id, email, subscription_id, status, period_end, updated_at)
VALUES(?, '', ?, ?, ?, ?)
ON CONFLICT(customer_id) DO UPDATE SET
	subscription_id = excluded.subscription_id,
	status = excluded.status,
	period_end = CASE WHEN excluded.period_end > 0 THEN excluded.period_end ELSE customers.period_end END,
	updated_at = excluded.updated_at
`, customerID, subscriptionID, status, periodEnd, now); err != nil {
		return fmt.Errorf("store: update subscription: %w", err)
	}

	return tx.Commit()
}

// MarkEventProcessed records eventID as handled with no associated write —
// used for webhook event types this service does not otherwise act on, so
// a redelivery of an ignored event is still recognized as a duplicate
// rather than re-evaluated every time.
func (s *Store) MarkEventProcessed(ctx context.Context, eventID string, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: mark event processed: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op once Commit succeeds (sql.ErrTxDone); the standard defer-Rollback idiom
	if err := markEventProcessed(ctx, tx, eventID, now); err != nil {
		return err
	}
	return tx.Commit()
}

// Customer is a resolved customer row, used by /reissue to decide whether
// a fresh token may be minted.
type Customer struct {
	CustomerID     string
	Email          string
	SubscriptionID string
	Status         string
	PeriodEnd      int64
}

// ErrCustomerNotFound is returned by CustomerByEmail when no customer row
// matches — /reissue reports this as "no subscription found" rather than
// distinguishing "never subscribed" from "typo'd email", on purpose: it
// must not leak which emails have an active subscription.
var ErrCustomerNotFound = errors.New("store: customer not found")

// CustomerByEmail returns the most recently updated customer row for
// email. Emails are not unique across customer_id in principle (a person
// could resubscribe with a new Stripe customer after a full cancellation),
// so this picks the most recently touched row, which is the one /reissue
// and a repeat Checkout should care about.
func (s *Store) CustomerByEmail(ctx context.Context, email string) (Customer, error) {
	var c Customer
	err := s.db.QueryRowContext(ctx, `
SELECT customer_id, email, subscription_id, status, period_end
FROM customers WHERE email = ?
ORDER BY updated_at DESC LIMIT 1
`, email).Scan(&c.CustomerID, &c.Email, &c.SubscriptionID, &c.Status, &c.PeriodEnd)
	if errors.Is(err, sql.ErrNoRows) {
		return Customer{}, ErrCustomerNotFound
	}
	if err != nil {
		return Customer{}, fmt.Errorf("store: customer by email: %w", err)
	}
	return c, nil
}
