package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	testUUID   = "testresourceuuid"
	testSecret = "test-webhook-secret"
	testRepo   = "example/site"
	testRef    = "refs/heads/main"
)

func TestWebhookQueuesOneDeployment(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/deploy" {
			t.Errorf("upstream request = %s %s", r.Method, r.URL)
		}
		if got := r.URL.Query().Get("uuid"); got != testUUID {
			t.Errorf("uuid = %q", got)
		}
		if got := r.URL.Query().Get("force"); got != "false" {
			t.Errorf("force = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer deploy-token" {
			t.Errorf("authorization = %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	g := testGateway(t, upstream.URL)
	body := []byte(`{"ref":"refs/heads/main","repository":{"full_name":"example/site"}}`)

	for _, delivery := range []string{"delivery-1", "delivery-2"} {
		request := signedRequest(body, "push", delivery)
		response := httptest.NewRecorder()
		g.handler().ServeHTTP(response, request)
		if response.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusAccepted)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
}

func TestWebhookRejectsTamperedAndInvalidRequests(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	g := testGateway(t, upstream.URL)
	body := []byte(`{"ref":"refs/heads/main","repository":{"full_name":"example/site"}}`)

	cases := []struct {
		name    string
		request *http.Request
		status  int
	}{
		{"invalid signature", signedRequestWithSecret(body, "push", "delivery-2", "wrong-secret"), http.StatusUnauthorized},
		{"force true", signedRequestWithURL(body, "push", "delivery-3", "/webhooks/source/github/manual?uuid="+testUUID+"&force=true"), http.StatusBadRequest},
		{"unknown uuid", signedRequestWithURL(body, "push", "delivery-4", "/webhooks/source/github/manual?uuid=unknown&force=false"), http.StatusNotFound},
		{"malformed query", signedRequestWithURL(body, "push", "delivery-5", "/webhooks/source/github/manual?uuid="+testUUID+"&force=false&bad=%zz"), http.StatusBadRequest},
		{"wrong ref", signedRequestWithSecret([]byte(`{"ref":"refs/heads/dev","repository":{"full_name":"example/site"}}`), "push", "delivery-6", testSecret), http.StatusUnprocessableEntity},
		{"deleted ref", signedRequestWithSecret([]byte(`{"ref":"refs/heads/main","deleted":true,"repository":{"full_name":"example/site"}}`), "push", "delivery-7", testSecret), http.StatusUnprocessableEntity},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			g.handler().ServeHTTP(response, test.request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0", got)
	}
}

func TestLoadConfigRequiresExplicitHTTPOptIn(t *testing.T) {
	env := map[string]string{
		"COOLIFY_BASE_URL":    "http://192.168.0.215:8000",
		"COOLIFY_API_TOKEN":   "deploy-token",
		"DEPLOY_TARGETS_JSON": `{"testresourceuuid":{"secret":"test-webhook-secret-0123456789abcdef","repository":"example/site","ref":"refs/heads/main"}}`,
	}
	getenv := func(key string) string { return env[key] }
	if _, err := loadConfig(getenv); err == nil {
		t.Fatal("insecure HTTP was accepted without explicit opt-in")
	}
	env["COOLIFY_ALLOW_INSECURE_HTTP"] = "true"
	if _, err := loadConfig(getenv); err != nil {
		t.Fatalf("explicit insecure HTTP opt-in failed: %v", err)
	}
	env["COOLIFY_BASE_URL"] = "http://example.com:8000"
	if _, err := loadConfig(getenv); err == nil {
		t.Fatal("public HTTP origin was accepted")
	}
	env["COOLIFY_BASE_URL"] = "http://192.168.0.215:8000"
	env["DEPLOY_TARGETS_JSON"] = `{"firsttarget":{"secret":"same-secret-0123456789abcdef0123456789","repository":"example/one","ref":"refs/heads/main"},"secondtarget":{"secret":"same-secret-0123456789abcdef0123456789","repository":"example/two","ref":"refs/heads/main"}}`
	if _, err := loadConfig(getenv); err == nil {
		t.Fatal("duplicate target secrets were accepted")
	}
}

func TestWebhookPongAndRouteBoundaries(t *testing.T) {
	g := testGateway(t, "http://127.0.0.1:1")
	body := []byte(`{"zen":"test"}`)

	request := signedRequest(body, "ping", "delivery-ping")
	response := httptest.NewRecorder()
	g.handler().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("ping status = %d, want %d", response.Code, http.StatusNoContent)
	}

	wrongPath := signedRequestWithURL(body, "ping", "delivery-path", "/webhooks/source/github/manual/extra?uuid="+testUUID+"&force=false")
	response = httptest.NewRecorder()
	g.handler().ServeHTTP(response, wrongPath)
	if response.Code != http.StatusNotFound {
		t.Fatalf("wrong path status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestDeliveryCacheSharesFailureWithConcurrentRetry(t *testing.T) {
	cache := &deliveryCache{entries: make(map[string]*delivery)}
	first, owner := cache.begin("target:fingerprint")
	if !owner {
		t.Fatal("first request was not the owner")
	}
	second, owner := cache.begin("target:fingerprint")
	if owner || second != first {
		t.Fatal("concurrent request did not join the in-flight delivery")
	}

	want := errors.New("upstream failed")
	cache.finish("target:fingerprint", want)
	if got := cache.wait(second); !errors.Is(got, want) {
		t.Fatalf("shared error = %v, want %v", got, want)
	}
}

func testGateway(t *testing.T, upstreamURL string) *gateway {
	t.Helper()
	base, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	return &gateway{
		config: config{
			CoolifyBase:  base,
			CoolifyToken: "deploy-token",
			Targets: map[string]target{
				testUUID: {Secret: testSecret, Repository: testRepo, Ref: testRef},
			},
		},
		client:     &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		deliveries: &deliveryCache{entries: make(map[string]*delivery)},
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func signedRequest(body []byte, event, delivery string) *http.Request {
	return signedRequestWithSecret(body, event, delivery, testSecret)
}

func signedRequestWithSecret(body []byte, event, delivery, secret string) *http.Request {
	return signedRequestWithURLAndSecret(body, event, delivery, "/webhooks/source/github/manual?uuid="+testUUID+"&force=false", secret)
}

func signedRequestWithURL(body []byte, event, delivery, path string) *http.Request {
	return signedRequestWithURLAndSecret(body, event, delivery, path, testSecret)
}

func signedRequestWithURLAndSecret(body []byte, event, delivery, path, secret string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Event", event)
	request.Header.Set("X-GitHub-Delivery", delivery)
	request.Header.Set("X-Hub-Signature-256", signature(body, secret))
	return request
}

func signature(body []byte, secret string) string {
	digest := hmac.New(sha256.New, []byte(secret))
	_, _ = digest.Write(body)
	return "sha256=" + hex.EncodeToString(digest.Sum(nil))
}
