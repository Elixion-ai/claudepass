package webhookfixture

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stripe/stripe-go/v86"
)

func TestRenderSubstitutesEveryPlaceholder(t *testing.T) {
	for _, name := range []string{CheckoutSessionCompleted, SubscriptionUpdated, SubscriptionDeleted} {
		body, err := Render(name, Values{
			EventID: "evt_x", SessionID: "cs_x", CustomerID: "cus_x", SubscriptionID: "sub_x",
			Email: "x@example.com", Created: time.Unix(1700000000, 0),
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !json.Valid(body) {
			t.Fatalf("%s: rendered fixture is not valid JSON:\n%s", name, body)
		}
		var raw map[string]any
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if raw["id"] != "evt_x" {
			t.Fatalf("%s: id = %v, want evt_x", name, raw["id"])
		}
	}
}

func TestRenderAppliesDefaultsWhenFieldsOmitted(t *testing.T) {
	body, err := Render(CheckoutSessionCompleted, Values{})
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(body) {
		t.Fatalf("defaulted fixture is not valid JSON:\n%s", body)
	}
}

func TestRenderUnknownFixture(t *testing.T) {
	if _, err := Render("does-not-exist", Values{}); err == nil {
		t.Fatal("expected an error for an unknown fixture name")
	}
}

// TestSignatureHeaderVerifiesWithStripeConstructEvent proves the header
// this package builds is byte-for-byte what stripe.ConstructEvent (the
// same call the server uses) accepts — the whole point of using stripe-go's
// own exported ComputeSignature rather than a hand-rolled HMAC.
func TestSignatureHeaderVerifiesWithStripeConstructEvent(t *testing.T) {
	body, err := Render(CheckoutSessionCompleted, Values{Created: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now()
	header := SignatureHeader("whsec_test", body, at)

	if _, err := stripe.ConstructEvent(body, header, "whsec_test", stripe.WithIgnoreAPIVersionMismatch()); err != nil {
		t.Fatalf("ConstructEvent rejected a signature this package produced: %v", err)
	}
	if _, err := stripe.ConstructEvent(body, header, "wrong_secret", stripe.WithIgnoreAPIVersionMismatch()); err == nil {
		t.Fatal("ConstructEvent should reject the wrong secret")
	}
}
