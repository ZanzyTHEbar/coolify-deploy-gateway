package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	webhookPath     = "/webhooks/source/github/manual"
	maxBodyBytes    = 1 << 20
	requestTimeout  = 8 * time.Second
	deliveryTTL     = 10 * time.Minute
	maxDeliveryID   = 128
	maxDeliveries   = 4096
	healthcheckAddr = "http://127.0.0.1:8080/healthz"
)

var resourceIDPattern = regexp.MustCompile(`^[a-z0-9]+$`)

type target struct {
	Secret     string `json:"secret"`
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
}

type config struct {
	ListenAddr   string
	CoolifyBase  *url.URL
	CoolifyToken string
	Targets      map[string]target
}

type delivery struct {
	done    chan struct{}
	err     error
	created time.Time
}

type deliveryCache struct {
	mu      sync.Mutex
	entries map[string]*delivery
}

type gateway struct {
	config     config
	client     *http.Client
	deliveries *deliveryCache
	log        *slog.Logger
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "check the local health endpoint")
	flag.Parse()
	if *healthcheck {
		if err := runHealthcheck(); err != nil {
			os.Exit(1)
		}
		return
	}

	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	app := &gateway{
		config:     cfg,
		client:     newHTTPClient(),
		deliveries: &deliveryCache{entries: make(map[string]*delivery)},
		log:        slog.Default(),
	}
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           app.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       requestTimeout,
		WriteTimeout:      requestTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	slog.Info("deploy gateway listening", "addr", cfg.ListenAddr, "targets", len(cfg.Targets))
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{
		Transport:     transport,
		Timeout:       requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func loadConfig(getenv func(string) string) (config, error) {
	listenAddr := getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	baseText := getenv("COOLIFY_BASE_URL")
	if baseText == "" {
		return config{}, fmt.Errorf("COOLIFY_BASE_URL is required")
	}
	base, err := url.Parse(strings.TrimRight(baseText, "/"))
	if err != nil || base.Host == "" || (base.Path != "" && base.Path != "/") || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Scheme != "http" && base.Scheme != "https") {
		return config{}, fmt.Errorf("COOLIFY_BASE_URL must be an http(s) origin")
	}
	if base.Scheme == "http" && getenv("COOLIFY_ALLOW_INSECURE_HTTP") != "true" {
		return config{}, fmt.Errorf("COOLIFY_ALLOW_INSECURE_HTTP=true is required for an http origin")
	}
	if base.Scheme == "http" && !isPrivateOrigin(base) {
		return config{}, fmt.Errorf("insecure HTTP is only allowed for a private origin")
	}

	token := strings.TrimSpace(getenv("COOLIFY_API_TOKEN"))
	if token == "" {
		return config{}, fmt.Errorf("COOLIFY_API_TOKEN is required")
	}

	var targets map[string]target
	if err := json.Unmarshal([]byte(getenv("DEPLOY_TARGETS_JSON")), &targets); err != nil || len(targets) == 0 {
		return config{}, fmt.Errorf("DEPLOY_TARGETS_JSON must be a non-empty JSON object")
	}
	secrets := make(map[string]string, len(targets))
	for uuid, item := range targets {
		if !resourceIDPattern.MatchString(uuid) || item.Secret == "" || item.Repository == "" || item.Ref == "" {
			return config{}, fmt.Errorf("invalid deploy target %q", uuid)
		}
		if len(item.Secret) < 32 {
			return config{}, fmt.Errorf("deploy target %q needs a secret of at least 32 characters", uuid)
		}
		if previous, ok := secrets[item.Secret]; ok {
			return config{}, fmt.Errorf("deploy targets %q and %q must use different secrets", previous, uuid)
		}
		secrets[item.Secret] = uuid
	}

	return config{
		ListenAddr:   listenAddr,
		CoolifyBase:  base,
		CoolifyToken: token,
		Targets:      targets,
	}, nil
}

func isPrivateOrigin(base *url.URL) bool {
	if ip := net.ParseIP(base.Hostname()); ip != nil {
		return ip.IsPrivate()
	}
	host := strings.TrimSuffix(strings.ToLower(base.Hostname()), ".")
	return strings.HasSuffix(host, ".home.arpa")
}

func (g *gateway) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST "+webhookPath, g.webhook)
	return mux
}

func (g *gateway) webhook(w http.ResponseWriter, r *http.Request) {
	query, err := parseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "invalid deployment request", http.StatusBadRequest)
		return
	}

	target, ok := g.config.Targets[query.uuid]
	if !ok {
		http.NotFound(w, r)
		return
	}

	if r.ContentLength > maxBodyBytes {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		http.Error(w, "JSON required", http.StatusUnsupportedMediaType)
		return
	}

	deliveryID := r.Header.Get("X-GitHub-Delivery")
	if deliveryID == "" || len(deliveryID) > maxDeliveryID || strings.TrimSpace(deliveryID) != deliveryID {
		http.Error(w, "invalid webhook", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !verifySignatureBytes(r.Header.Get("X-Hub-Signature-256"), target.Secret, body) {
		http.Error(w, "invalid webhook", http.StatusUnauthorized)
		return
	}

	event := strings.ToLower(r.Header.Get("X-GitHub-Event"))
	if event == "ping" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if event != "push" || !matchesTarget(body, target) {
		http.Error(w, "unsupported webhook", http.StatusUnprocessableEntity)
		return
	}

	deliveryKey := deliveryFingerprint(query.uuid, body)
	state, owner := g.deliveries.begin(deliveryKey)
	if !owner {
		if err := g.deliveries.wait(state); err != nil {
			http.Error(w, "deployment unavailable", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if err := g.deploy(r, query.uuid, query.force); err != nil {
		g.deliveries.finish(deliveryKey, err)
		g.log.Error("coolify deployment request failed", "uuid", query.uuid, "error", err)
		http.Error(w, "deployment unavailable", http.StatusBadGateway)
		return
	}
	g.deliveries.finish(deliveryKey, nil)

	g.log.Info("coolify deployment queued", "uuid", query.uuid, "delivery", deliveryID)
	w.WriteHeader(http.StatusAccepted)
}

type deploymentQuery struct {
	uuid  string
	force bool
}

func parseQuery(rawQuery string) (deploymentQuery, error) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return deploymentQuery{}, fmt.Errorf("invalid query")
	}
	if len(values) != 2 || len(values["uuid"]) != 1 || len(values["force"]) != 1 {
		return deploymentQuery{}, fmt.Errorf("uuid and force are required")
	}
	if values.Get("force") != "false" {
		return deploymentQuery{}, fmt.Errorf("force must be false")
	}
	if !resourceIDPattern.MatchString(values.Get("uuid")) {
		return deploymentQuery{}, fmt.Errorf("invalid uuid")
	}
	return deploymentQuery{uuid: values.Get("uuid"), force: false}, nil
}

func deliveryFingerprint(uuid string, body []byte) string {
	digest := sha256.Sum256(body)
	return uuid + ":" + hex.EncodeToString(digest[:])
}

func verifySignatureBytes(header, secret string, body []byte) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) || len(header) != len(prefix)+sha256.Size*2 {
		return false
	}
	actual, err := hex.DecodeString(header[len(prefix):])
	if err != nil {
		return false
	}
	digest := hmac.New(sha256.New, []byte(secret))
	_, _ = digest.Write(body)
	return hmac.Equal(actual, digest.Sum(nil))
}

func matchesTarget(body []byte, target target) bool {
	var payload struct {
		Ref        string `json:"ref"`
		Deleted    bool   `json:"deleted"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}
	return json.Unmarshal(body, &payload) == nil && !payload.Deleted && payload.Ref == target.Ref && payload.Repository.FullName == target.Repository
}

func (g *gateway) deploy(r *http.Request, uuid string, force bool) error {
	endpoint := *g.config.CoolifyBase
	endpoint.Path = "/api/v1/deploy"
	endpoint.RawQuery = url.Values{
		"uuid":  {uuid},
		"force": {strconv.FormatBool(force)},
	}.Encode()

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+g.config.CoolifyToken)
	response, err := g.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("coolify returned status %d", response.StatusCode)
	}
	return nil
}

func runHealthcheck() error {
	client := http.Client{Timeout: 2 * time.Second}
	response, err := client.Get(healthcheckAddr)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("health endpoint returned status %d", response.StatusCode)
	}
	return nil
}

func (c *deliveryCache) begin(id string) (*delivery, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for key, added := range c.entries {
		if now.Sub(added.created) >= deliveryTTL {
			delete(c.entries, key)
		}
	}
	if existing, ok := c.entries[id]; ok {
		return existing, false
	}
	if len(c.entries) >= maxDeliveries {
		return nil, false
	}
	entry := &delivery{done: make(chan struct{}), created: now}
	c.entries[id] = entry
	return entry, true
}

func (c *deliveryCache) finish(id string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[id]
	if !ok {
		return
	}
	entry.err = err
	close(entry.done)
	if err != nil {
		delete(c.entries, id)
	}
}

func (c *deliveryCache) wait(entry *delivery) error {
	if entry == nil {
		return fmt.Errorf("delivery cache is full")
	}
	<-entry.done
	return entry.err
}
