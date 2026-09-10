package detect

import (
	"fmt"
	"strings"
	"testing"
)

// Positive corpus: each line must yield at least one Match. Where the line
// is expected to resolve to a known provider Handle, wantHandle names it;
// an empty wantHandle means only the generic entropy path should fire.
var positiveCorpus = []struct {
	name       string
	text       string
	wantHandle string
}{
	{"stripe live inline", "here's the key: sk_live_51H8xJ2eZvKYlo2CTESTabcdefghijklmno please use it", "stripe/live"},
	{"stripe live bare", "sk_live_51H8xJ2eZvKYlo2CTESTabcdefghijklmno", "stripe/live"},
	{"stripe test", "STRIPE_KEY=sk_test_51H8xJ2eZvKYlo2CTESTabcdefghijklmno", "stripe/test"},
	{"github ghp", "export GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz12", "github/token"},
	{"github gho", "Authorization: token gho_1234567890abcdefghijklmnopqrstuvwxyz12", "github/token"},
	{"github fine-grained pat", "github_pat_11AAAAAAA0abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX is my token", "github/token"},
	{"aws access key", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "aws/access-key"},
	{"aws access key inline prose", "our access key is AKIAIOSFODNN7EXAMPLE, rotate quarterly", "aws/access-key"},
	{"anthropic key", "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD", "anthropic/key"},
	{"openai key", "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN12", "openai/key"},
	{"slack bot token", "SLACK_BOT_TOKEN=xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx", "slack/token"},
	{"slack user token", "token: xoxp-1234567890-1234567890123-abcdefghijklmnopqrstuvwx", "slack/token"},
	{"google api key", "AIzaSyDaGmWKa4JsXZHjGw7ISLn3namBGewQeExample", "google/api-key"},
	{"pem rsa private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1c7+9z5Pad7OD0GYNGgtqXWJ+aTVTT1Z3sJoK7oGxlKQ\nrKJj9j0kOhz8XT4qN2vB3wYh0uJj5mL8qF2xW9rC4dK7pS1tE6yV3zA0bH2n\n-----END RSA PRIVATE KEY-----", "pem/key"},
	{"pem generic private key", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB\nwQNKWaRxujjxXtb2m1r6mNbahoLE0FzTaZL+7SDDOa2GY0mB2E37NdgHkJdvhKrl\n-----END PRIVATE KEY-----", "pem/key"},
	{"entropy random token 1", "the deploy secret is aB3xQ9mK2pL7vN4zR8tY1wU6sD0fG5hJ3kM, keep it safe", ""},
	{"entropy random token 2", "temp value 7fKx2mQ8pL3nR5vT1wY6uD0zS4gH9jM2kAe was pasted by mistake", ""},
	{"entropy random token 3", "X-Api-Secret: n9Vb2Km5Qp8Lr1St4Wx7Yz0Ac3Ef6Gh9Jk2Mn5Pq8Rs1Tv4", ""},
	{"entropy random token 4", "Zk7Qm2Xp9Lb4Vn6Rt1Sy8Wu3Dc5Fh0Gj2Ka4Me7Np9Qr1", ""},
	{"entropy random token 5", "9mK2pL7vN4zR8tY1wU6sD0fG5hJ3kMaB3xQ7cE1oI4uY6", ""},
	{"entropy random token 6", "auth=Hs7Kp2Lm9Qw4Rt6Vy1Zc3Bd8Fg0Jn5", ""},
	{"jwt-like token", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PYVDp7ph_YXo", ""},
	{"generic db password", "DB_PASSWORD=Tr7mK9pQ2vL4xN8wR1zY6bC3sF5Hj8", ""},
	{"multi hit same line", "sk_live_51H8xJ2eZvKYlo2CTESTabcdefghijklmno and ghp_1234567890abcdefghijklmnopqrstuvwxyz12 both leaked", "stripe/live"},
	{"random token in json", `{"token":"Qp8Lr1St4Wx7Yz0Ac3Ef6Gh9Jk2Mn5Pq8Rs1Tv4Uw7"}`, ""},
	{"random token in yaml", "api_key: Vb2Km5Qp8Lr1St4Wx7Yz0Ac3Ef6Gh9Jk2Mn5", ""},
	{"random token trailing punctuation", "leaked: Xk4Qp9Lm2Rt7Vy1Zc3Bd8Fg0Jn5Hs7Kp2Lm9Qw!", ""},
	{"random token with slash", "creds/aB3xQ9mK2pL7vN4zR8tY1wU6sD0fG5hJ3kM/prod", ""},
	{"aws secret access key", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ""},
	// CLA-30: a Secret genuinely embedded in a URL query string must still
	// be caught by the generic entropy path — the query string sits past
	// urlPathRanges' cutoff at "?", so only the ordinary path is excluded.
	{"secret in url query string", "GET https://api.example.com/v1/upload?token=aB3xQ9mK2pL7vN4zR8tY1wU6sD0fG5hJ3kM HTTP/1.1", ""},
}

// Negative corpus: none of these ordinary code/prose lines may produce a
// Match. False positives here are a hard failure per the acceptance bar.
var negativeCorpus = []string{
	"The quick brown fox jumps over the lazy dog while the API documentation loads slowly.",
	"func calculateTotalPriceForCustomerOrder(customerID int) (float64, error) {",
	"SELECT * FROM users WHERE created_at > '2024-01-01' ORDER BY id DESC LIMIT 100;",
	`git commit -m "Fix flaky test in redact/writer_test.go and update docs"`,
	"Request ID: 550e8400-e29b-41d4-a716-446655440000 processed successfully",
	"Merged commit 9474de4b3f21a0c8d5e6f7a8b9c0d1e2f3a4b5c6 into main",
	"thisIsAVeryLongDescriptiveVariableNameForTheConfigurationLoader",
	"MAX_RETRY_ATTEMPTS_BEFORE_GIVING_UP_ON_CONNECTION = 5",
	"/usr/local/var/log/claudepass/redactions.log rotated at midnight",
	"https://docs.anthropic.com/en/docs/claude-code/hooks-guide#userpromptsubmit",
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.",
	`{"name": "grigori", "role": "engineer", "active": true}`,
	"aGVsbG8gd29ybGQ=",
	"// TODO: refactor this handler to use the new Broker interface",
	"## Intercept engine and Exposed tracking",
	"state-of-the-art machine-learning-based anomaly-detection system",
	"import (\n\t\"encoding/json\"\n\t\"net/http\"\n)",
	"export DATABASE_URL=postgres://localhost:5432/mydb",
	"claudepass v1.4.2-beta.3 released on 2026-09-09",
	"abcdefghijklmnopqrstuvwxyz0123456789abcdefghij",
	"Server listening on [2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080",
	"timeout_seconds: 30\nmax_connections: 100\nretry_backoff: exponential",
	"This function computes the SHA-256 digest of the given input buffer and returns hex.",
	"userAuthenticationHandlerV2ForOAuthTokenValidationFlow",
	"convertUserInputStringToBase64EncodedByteArrayForV3ApiRequest",
	"Why does the redaction writer flush after 100 milliseconds instead of immediately?",
	"#!/usr/bin/env bash\nset -euo pipefail",
	"Account number 1234567890123456789012345",
	"| Name | Age | City |\n| Alice | 30 | NYC |",
	`cpass run --with stripe/live -- curl -H "Authorization: Bearer <token>" https://api.example.com`,
	"claudepass-v1.4.2-beta.3-release-candidate-build",
	"the AKIA acronym stands for access key ID, not a value on its own",
	"a token named sk in this codebase refers to a syntax kind, not a Secret",
	// CLA-30: ordinary REST call URLs whose path has a numbered or
	// hex-ish segment, straight from the issue report.
	"https://api.stripe.com/v1/charges",
	"GET https://api.example.com/users/507f1f77bcf86cd799439011 returned 200",
	`curl https://api.github.com/repos/anthropics/claude-code/issues/1234`,
	"https://storage.googleapis.com/my-bucket/uploads/20240115/a1b2c3d4e5f6789012345678",
	`cpass run --with stripe/live -- curl -H "Authorization: Bearer $STRIPE_LIVE" https://api.stripe.com/v1/charges/ch_3Oq5x2AbCdEfGh011`,
}

func TestPositiveCorpus(t *testing.T) {
	if len(positiveCorpus) < 25 {
		t.Fatalf("positive corpus too small: %d", len(positiveCorpus))
	}
	for _, c := range positiveCorpus {
		t.Run(c.name, func(t *testing.T) {
			matches := Scan(c.text)
			if len(matches) == 0 {
				t.Fatalf("no match found in %q", c.text)
			}
			if c.wantHandle != "" {
				found := false
				for _, m := range matches {
					if m.Handle == c.wantHandle {
						found = true
					}
				}
				if !found {
					t.Fatalf("want handle %s, got matches %+v", c.wantHandle, matches)
				}
			}
			for _, m := range matches {
				if m.Kind == "" {
					t.Fatalf("match %+v has no Kind", m)
				}
			}
		})
	}
}

func TestNegativeCorpusZeroFalsePositives(t *testing.T) {
	if len(negativeCorpus) < 25 {
		t.Fatalf("negative corpus too small: %d", len(negativeCorpus))
	}
	for i, text := range negativeCorpus {
		t.Run(fmt.Sprintf("line-%02d", i), func(t *testing.T) {
			if matches := Scan(text); len(matches) != 0 {
				t.Fatalf("false positive on %q: %+v", text, matches)
			}
		})
	}
}

func TestBypassPrefixDoesNotAffectScan(t *testing.T) {
	// Scan itself is prefix-agnostic; !! handling lives in the intercept
	// command. Sanity check that a bypass-prefixed prompt still scans the
	// remaining text normally.
	text := "!! sk_live_51H8xJ2eZvKYlo2CTESTabcdefghijklmno"
	matches := Scan(text)
	if len(matches) != 1 || matches[0].Handle != "stripe/live" {
		t.Fatalf("matches: %+v", matches)
	}
}

func TestValueNeverTruncatedOrMutated(t *testing.T) {
	raw := "sk_live_51H8xJ2eZvKYlo2CTESTabcdefghijklmno"
	matches := Scan(raw)
	if len(matches) != 1 || matches[0].Value != raw {
		t.Fatalf("value should round-trip exactly: %+v", matches)
	}
}

func TestPEMValueSpansWholeBlock(t *testing.T) {
	text := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw\n-----END PRIVATE KEY-----"
	matches := Scan(text)
	if len(matches) != 1 {
		t.Fatalf("want exactly one PEM match, got %+v", matches)
	}
	if !strings.HasPrefix(matches[0].Value, "-----BEGIN PRIVATE KEY-----") || !strings.HasSuffix(matches[0].Value, "-----END PRIVATE KEY-----") {
		t.Fatalf("value should span the whole block: %q", matches[0].Value)
	}
}
