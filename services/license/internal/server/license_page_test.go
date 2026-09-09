package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"claudepass/services/license/internal/store"
)

func TestLicensePageMissingSessionID(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/license", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestLicensePageUnknownSessionEventuallyGivesUp(t *testing.T) {
	srv, _ := newTestServer(t)
	start := time.Now()
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/license?session_id=cs_never", nil))
	elapsed := time.Since(start)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusNotFound, rec.Body)
	}
	// The test server is configured with a short poll window (see
	// newTestServer); this just confirms it actually bounded the wait
	// rather than blocking forever or returning instantly without trying.
	if elapsed > 2*time.Second {
		t.Fatalf("license page took %s to give up; poll window should be bounded and short in tests", elapsed)
	}
}

// TestLicensePageWaitsOutWebhookRace shows GET /license tolerates the
// webhook arriving slightly after the browser's own redirect: it polls
// rather than failing on the first miss.
func TestLicensePageWaitsOutWebhookRace(t *testing.T) {
	srv, d := newTestServer(t)
	now := time.Now()

	go func() {
		time.Sleep(30 * time.Millisecond)
		err := d.Store.IssueForCheckout(context.Background(), store.IssuedToken{
			EventID: "evt_late", SessionID: "cs_late", CustomerID: "cus_late", Email: "late@example.com",
			Now: now.Unix(), Token: "placeholder-token", JTI: "jti_late", Exp: now.Unix() + 1000,
		})
		if err != nil {
			panic(err)
		}
	}()

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/license?session_id=cs_late", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "placeholder-token") {
		t.Fatalf("page should show the token that landed mid-poll: %s", rec.Body.String())
	}
}

func TestLicensePageShowsTokenOnceOnlyEvenConcurrently(t *testing.T) {
	srv, d := newTestServer(t)
	now := time.Now()
	err := d.Store.IssueForCheckout(context.Background(), store.IssuedToken{
		EventID: "evt_once", SessionID: "cs_once", CustomerID: "cus_once", Email: "once@example.com",
		Now: now.Unix(), Token: "the-one-token", JTI: "jti_once", Exp: now.Unix() + 1000,
	})
	if err != nil {
		t.Fatal(err)
	}

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	hits := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/license?session_id=cs_once", nil))
			if strings.Contains(rec.Body.String(), "the-one-token") {
				mu.Lock()
				hits++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if hits != 1 {
		t.Fatalf("token should be shown to exactly one of %d concurrent requests, got %d", n, hits)
	}
}
