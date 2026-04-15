package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"range-scout/internal/dnstt"
	"range-scout/internal/model"
)

type request struct {
	Config    requestConfig   `json:"config"`
	Resolvers []model.Resolver `json:"resolvers"`
}

type requestConfig struct {
	Workers         int      `json:"workers"`
	TimeoutMS       int      `json:"timeout_ms"`
	E2ETimeoutS     int      `json:"e2e_timeout_s"`
	Port            int      `json:"port"`
	Transport       string   `json:"transport"`
	ResolverURL     string   `json:"resolver_url"`
	Domain          string   `json:"domain"`
	Pubkey          string   `json:"pubkey"`
	QuerySize       int      `json:"query_size"`
	E2EURL          string   `json:"e2e_url"`
	SOCKSUsername   string   `json:"socks_username"`
	SOCKSPassword   string   `json:"socks_password"`
	ScoreThreshold  int      `json:"score_threshold"`
	TestNearbyIPs   bool     `json:"test_nearby_ips"`
	BasePrefixes    []string `json:"base_prefixes"`
}

type responseEvent struct {
	Type    string          `json:"type"`
	Message string          `json:"message,omitempty"`
	Resolver *model.Resolver `json:"resolver,omitempty"`
	Summary *summaryPayload `json:"summary,omitempty"`
}

type summaryPayload struct {
	Candidates uint64 `json:"candidates"`
	Checked    uint64 `json:"checked"`
	TunnelOK   uint64 `json:"tunnel_ok"`
	E2EOK      uint64 `json:"e2e_ok"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	decoder := json.NewDecoder(os.Stdin)
	var input request
	if err := decoder.Decode(&input); err != nil {
		emitFatal(fmt.Errorf("decode request: %w", err))
	}

	cfg := dnstt.Config{
		Workers:        input.Config.Workers,
		Timeout:        time.Duration(input.Config.TimeoutMS) * time.Millisecond,
		E2ETimeout:     time.Duration(input.Config.E2ETimeoutS) * time.Second,
		Port:           input.Config.Port,
		Transport:      dnstt.Transport(strings.TrimSpace(input.Config.Transport)),
		ResolverURL:    strings.TrimSpace(input.Config.ResolverURL),
		Domain:         strings.TrimSpace(input.Config.Domain),
		Pubkey:         strings.TrimSpace(input.Config.Pubkey),
		QuerySize:      input.Config.QuerySize,
		E2EURL:         strings.TrimSpace(input.Config.E2EURL),
		SOCKSUsername:  strings.TrimSpace(input.Config.SOCKSUsername),
		SOCKSPassword:  input.Config.SOCKSPassword,
		ScoreThreshold: input.Config.ScoreThreshold,
		TestNearbyIPs:  input.Config.TestNearbyIPs,
		BasePrefixes:   input.Config.BasePrefixes,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)

	var mu sync.Mutex
	emit := func(event responseEvent) {
		mu.Lock()
		defer mu.Unlock()
		if err := encoder.Encode(event); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
		}
	}

	updated, summary, err := dnstt.Test(ctx, input.Resolvers, cfg, func(event dnstt.Event) {
		converted := responseEvent{
			Type: strings.ToLower(string(event.Type)),
		}
		if event.Item != nil {
			copyResolver := *event.Item
			converted.Resolver = &copyResolver
		}
		converted.Summary = toSummaryPayload(event.Summary)
		emit(converted)
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(130)
		}
		emit(responseEvent{
			Type:    "error",
			Message: err.Error(),
			Summary: toSummaryPayload(summary),
		})
		os.Exit(1)
	}

	emit(responseEvent{
		Type:    "complete",
		Summary: toSummaryPayload(summary),
	})

	_ = updated
}

func toSummaryPayload(summary dnstt.Summary) *summaryPayload {
	return &summaryPayload{
		Candidates: summary.Candidates,
		Checked:    summary.Checked,
		TunnelOK:   summary.TunnelOK,
		E2EOK:      summary.E2EOK,
		StartedAt:  formatTime(summary.StartedAt),
		FinishedAt: formatTime(summary.FinishedAt),
	}
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func emitFatal(err error) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(responseEvent{
		Type:    "error",
		Message: err.Error(),
	})
	os.Exit(1)
}
