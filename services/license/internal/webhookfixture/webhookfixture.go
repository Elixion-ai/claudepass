// Package webhookfixture renders the recorded Stripe webhook payloads
// under testdata/ into concrete event bodies, and signs them the same way
// Stripe itself does. It exists so both the server package's handler tests
// and the top-level end-to-end test share one source of fixture data and
// one signing implementation, instead of each re-deriving the HMAC scheme.
//
// The fixtures are trimmed, hand-authored JSON shaped exactly like the
// bodies `stripe listen`/`stripe trigger` deliver for
// checkout.session.completed, customer.subscription.updated and
// customer.subscription.deleted (CLA-15's "no live Stripe" constraint), not
// a capture off a real Stripe account.
package webhookfixture

import (
	"embed"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/stripe/stripe-go/v86"
)

//go:embed testdata/*.json
var fixturesFS embed.FS

// Fixture names, one per file under testdata/.
const (
	CheckoutSessionCompleted = "checkout_session_completed"
	SubscriptionUpdated      = "subscription_updated"
	SubscriptionDeleted      = "subscription_deleted"
)

// Values fills in the placeholders common to all three fixtures. Zero
// fields get a sensible default (see Render) so a test only sets what it
// cares about.
type Values struct {
	EventID           string
	SessionID         string
	CustomerID        string
	SubscriptionID    string
	Email             string
	BaseURL           string
	Created           time.Time
	PeriodStart       time.Time
	PeriodEnd         time.Time
	PreviousPeriodEnd time.Time
}

// Render loads the named fixture and substitutes v's fields for its
// {{PLACEHOLDER}} tokens. Substitution is plain string replacement, not
// text/template, because the fixtures are recorded JSON payloads, not Go
// templates: this way a fixture file reads exactly like the real webhook
// body it stands in for.
func Render(name string, v Values) ([]byte, error) {
	raw, err := fixturesFS.ReadFile("testdata/" + name + ".json")
	if err != nil {
		return nil, fmt.Errorf("webhookfixture: unknown fixture %q: %w", name, err)
	}

	def := func(s, fallback string) string {
		if s == "" {
			return fallback
		}
		return s
	}
	defTime := func(t time.Time, fallback time.Time) time.Time {
		if t.IsZero() {
			return fallback
		}
		return t
	}

	now := time.Now()
	created := defTime(v.Created, now)
	periodStart := defTime(v.PeriodStart, created)
	periodEnd := defTime(v.PeriodEnd, created.Add(31*24*time.Hour))
	prevPeriodEnd := defTime(v.PreviousPeriodEnd, created)

	r := strings.NewReplacer(
		"{{EVENT_ID}}", def(v.EventID, "evt_test_"+strconv.FormatInt(now.UnixNano(), 36)),
		"{{SESSION_ID}}", def(v.SessionID, "cs_test_1"),
		"{{CUSTOMER_ID}}", def(v.CustomerID, "cus_test_1"),
		"{{SUBSCRIPTION_ID}}", def(v.SubscriptionID, "sub_test_1"),
		"{{EMAIL}}", def(v.Email, "dev@example.com"),
		"{{BASE_URL}}", def(v.BaseURL, "https://license.example.test"),
		"{{CREATED}}", strconv.FormatInt(created.Unix(), 10),
		"{{PERIOD_START}}", strconv.FormatInt(periodStart.Unix(), 10),
		"{{PERIOD_END}}", strconv.FormatInt(periodEnd.Unix(), 10),
		"{{PREVIOUS_PERIOD_END}}", strconv.FormatInt(prevPeriodEnd.Unix(), 10),
	)
	return []byte(r.Replace(string(raw))), nil
}

// SignatureHeader builds the value of a Stripe-Signature header for
// payload, the same way Stripe signs a real webhook delivery: HMAC-SHA256
// over "{timestamp}.{payload}" with the endpoint's signing secret. This
// uses stripe-go's own exported ComputeSignature so the test signature and
// the server's stripe.ConstructEvent verification share one
// implementation.
func SignatureHeader(secret string, payload []byte, at time.Time) string {
	sig := stripe.ComputeSignature(at, payload, secret)
	return fmt.Sprintf("t=%d,v1=%x", at.Unix(), sig)
}
