package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() }) // best-effort cleanup
	return s
}

// issueForCheckout is a thin positional wrapper around IssueForCheckout's
// struct argument, so the many call sites below that don't care about the
// jti/exp audit fields can keep passing the fields they do care about in a
// line; jti is derived from eventID, which every caller already makes
// unique per call.
func issueForCheckout(ctx context.Context, s *Store, eventID, sessionID, customerID, email string, periodEnd, now int64, token string) error {
	return s.IssueForCheckout(ctx, IssuedToken{
		EventID: eventID, SessionID: sessionID, CustomerID: customerID, Email: email,
		PeriodEnd: periodEnd, Now: now, Token: token,
		JTI: eventID + "_jti", Exp: now + 1000,
	})
}

func TestIssueForCheckoutThenTakeTokenOnce(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := issueForCheckout(ctx, s, "evt_1", "cs_1", "cus_1", "a@example.com", 1000, 500, "tok-1"); err != nil {
		t.Fatal(err)
	}

	got, err := s.TakeCheckoutToken(ctx, "cs_1")
	if err != nil {
		t.Fatalf("first take: %v", err)
	}
	if got.Token != "tok-1" {
		t.Fatalf("token = %q, want tok-1", got.Token)
	}
	if got.Email != "a@example.com" {
		t.Fatalf("email = %q, want a@example.com", got.Email)
	}
	if got.PeriodEnd != 1000 {
		t.Fatalf("period end = %d, want 1000", got.PeriodEnd)
	}

	if _, err := s.TakeCheckoutToken(ctx, "cs_1"); !errors.Is(err, ErrTokenAlreadyShown) {
		t.Fatalf("second take: err = %v, want ErrTokenAlreadyShown", err)
	}
}

func TestTakeCheckoutTokenUnknownSession(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.TakeCheckoutToken(context.Background(), "cs_missing"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("err = %v, want ErrTokenNotFound", err)
	}
}

func TestMarkEventProcessedIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.MarkEventProcessed(ctx, "evt_1", 100); err != nil {
		t.Fatalf("first mark: %v", err)
	}
	if err := s.MarkEventProcessed(ctx, "evt_1", 200); !errors.Is(err, ErrAlreadyProcessed) {
		t.Fatalf("second mark: err = %v, want ErrAlreadyProcessed", err)
	}
	// A different event id is independent.
	if err := s.MarkEventProcessed(ctx, "evt_2", 100); err != nil {
		t.Fatalf("different event: %v", err)
	}
}

func TestUpdateSubscriptionCreatesRowWhenCustomerUnknown(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.UpdateSubscription(ctx, "evt_new", "cus_new", "sub_new", StatusActive, 2000, 1000); err != nil {
		t.Fatal(err)
	}
	// There's no direct getter by customer id in the public API (only by
	// email, which a subscription event does not carry) — round-trip via
	// IssueForCheckout's upsert semantics instead: it must preserve the
	// status/period_end already recorded when a checkout event later fills
	// in the email for the same customer.
	if err := issueForCheckout(ctx, s, "evt_new_checkout", "cs_new", "cus_new", "new@example.com", 0, 1500, "tok"); err != nil {
		t.Fatal(err)
	}
	c, err := s.CustomerByEmail(ctx, "new@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.CustomerID != "cus_new" {
		t.Fatalf("customer_id = %q, want cus_new", c.CustomerID)
	}
}

func TestUpdateSubscriptionMarksCanceled(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := issueForCheckout(ctx, s, "evt_c1", "cs_c", "cus_c", "c@example.com", 5000, 1000, "tok"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSubscription(ctx, "evt_c2", "cus_c", "sub_c", StatusCanceled, 5000, 2000); err != nil {
		t.Fatal(err)
	}
	c, err := s.CustomerByEmail(ctx, "c@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != StatusCanceled {
		t.Fatalf("status = %q, want %q", c.Status, StatusCanceled)
	}
}

func TestUpdateSubscriptionKeepsKnownPeriodEndWhenNewValueUnknown(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := issueForCheckout(ctx, s, "evt_p1", "cs_p", "cus_p", "p@example.com", 9000, 1000, "tok"); err != nil {
		t.Fatal(err)
	}
	// A subsequent event with periodEnd=0 (e.g. an unexpanded subscription
	// reference) must not clobber the previously known value.
	if err := s.UpdateSubscription(ctx, "evt_p2", "cus_p", "sub_p", StatusActive, 0, 2000); err != nil {
		t.Fatal(err)
	}
	c, err := s.CustomerByEmail(ctx, "p@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.PeriodEnd != 9000 {
		t.Fatalf("period_end = %d, want 9000 (preserved)", c.PeriodEnd)
	}
}

func TestUpdateSubscriptionIdempotentOnDuplicateEvent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := issueForCheckout(ctx, s, "evt_d1", "cs_d", "cus_d", "d2@example.com", 1000, 500, "tok"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSubscription(ctx, "evt_d2", "cus_d", "sub_d", StatusCanceled, 1000, 600); err != nil {
		t.Fatal(err)
	}
	// A redelivery of the same event must not be applied twice, and must
	// report ErrAlreadyProcessed so the caller acks 200 without re-running
	// any side effect.
	if err := s.UpdateSubscription(ctx, "evt_d2", "cus_d", "sub_d", StatusActive, 9999, 700); !errors.Is(err, ErrAlreadyProcessed) {
		t.Fatalf("redelivered event: err = %v, want ErrAlreadyProcessed", err)
	}
	c, err := s.CustomerByEmail(ctx, "d2@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != StatusCanceled || c.PeriodEnd != 1000 {
		t.Fatalf("redelivered event must not have changed state: status=%q period_end=%d", c.Status, c.PeriodEnd)
	}
}

func TestCustomerByEmailNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.CustomerByEmail(context.Background(), "nobody@example.com"); !errors.Is(err, ErrCustomerNotFound) {
		t.Fatalf("err = %v, want ErrCustomerNotFound", err)
	}
}

func TestIssueForCheckoutSameEventRedeliveredIsRefused(t *testing.T) {
	// A genuine Stripe redelivery carries the same event id. It must not
	// be re-applied — this is what stops a slow-200-turned-retry from
	// re-populating an already-shown, already-cleared token.
	s := newTestStore(t)
	ctx := context.Background()

	if err := issueForCheckout(ctx, s, "evt_dup", "cs_dup", "cus_dup", "d@example.com", 1000, 500, "tok-a"); err != nil {
		t.Fatal(err)
	}
	if err := issueForCheckout(ctx, s, "evt_dup", "cs_dup", "cus_dup", "d@example.com", 1000, 600, "tok-b"); !errors.Is(err, ErrAlreadyProcessed) {
		t.Fatalf("redelivered event: err = %v, want ErrAlreadyProcessed", err)
	}
	got, err := s.TakeCheckoutToken(ctx, "cs_dup")
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "tok-a" {
		t.Fatalf("token = %q, want the original tok-a; the redelivery must not have overwritten it", got.Token)
	}
}

func TestIssueForCheckoutUpsertsSessionAcrossDistinctEvents(t *testing.T) {
	// Belt-and-suspenders on the storage layer itself: even for two
	// genuinely different event ids that happen to name the same
	// session_id (not a real Stripe scenario, but the schema should not
	// silently corrupt if it ever happened), the later write wins cleanly
	// rather than erroring on the checkout_tokens primary key.
	s := newTestStore(t)
	ctx := context.Background()

	if err := issueForCheckout(ctx, s, "evt_a", "cs_multi", "cus_multi", "m@example.com", 1000, 500, "tok-a"); err != nil {
		t.Fatal(err)
	}
	if err := issueForCheckout(ctx, s, "evt_b", "cs_multi", "cus_multi", "m@example.com", 1000, 600, "tok-b"); err != nil {
		t.Fatal(err)
	}
	got, err := s.TakeCheckoutToken(ctx, "cs_multi")
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "tok-b" {
		t.Fatalf("token = %q, want the latest issued token tok-b", got.Token)
	}
}

// issuedTokenRow reads back an issued_tokens row directly (white-box: this
// table has no public getter, since only RecordIssuedToken/IssueForCheckout
// need to write it — CLA-15's "SQLite stores customer→jti", checked here).
func issuedTokenRow(t *testing.T, s *Store, jti string) (customerID string, issuedAt, exp int64) {
	t.Helper()
	err := s.db.QueryRow(`SELECT customer_id, issued_at, exp FROM issued_tokens WHERE jti = ?`, jti).
		Scan(&customerID, &issuedAt, &exp)
	if err != nil {
		t.Fatalf("issued_tokens row for %q: %v", jti, err)
	}
	return customerID, issuedAt, exp
}

func TestIssueForCheckoutRecordsCustomerToJTI(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.IssueForCheckout(ctx, IssuedToken{
		EventID: "evt_jti1", SessionID: "cs_jti1", CustomerID: "cus_jti1", Email: "j@example.com",
		PeriodEnd: 5000, Now: 1000, Token: "tok", JTI: "jti-1", Exp: 8000,
	}); err != nil {
		t.Fatal(err)
	}

	customerID, issuedAt, exp := issuedTokenRow(t, s, "jti-1")
	if customerID != "cus_jti1" || issuedAt != 1000 || exp != 8000 {
		t.Fatalf("issued_tokens row = (%q, %d, %d), want (cus_jti1, 1000, 8000)", customerID, issuedAt, exp)
	}

	// The jti record must survive the token itself being shown and cleared
	// — it's the audit trail CLA-15 asks for, independent of the one-time
	// display in checkout_tokens.
	if _, err := s.TakeCheckoutToken(ctx, "cs_jti1"); err != nil {
		t.Fatal(err)
	}
	customerID, _, _ = issuedTokenRow(t, s, "jti-1")
	if customerID != "cus_jti1" {
		t.Fatalf("issued_tokens row should survive TakeCheckoutToken, got customer_id = %q", customerID)
	}
}

func TestRecordIssuedTokenForReissue(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.RecordIssuedToken(ctx, "jti-reissue", "cus_reissue", 2000, 9000); err != nil {
		t.Fatal(err)
	}
	customerID, issuedAt, exp := issuedTokenRow(t, s, "jti-reissue")
	if customerID != "cus_reissue" || issuedAt != 2000 || exp != 9000 {
		t.Fatalf("issued_tokens row = (%q, %d, %d), want (cus_reissue, 2000, 9000)", customerID, issuedAt, exp)
	}
}
