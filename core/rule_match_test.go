package main

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules"
	RW "github.com/metacubex/mihomo/rules/wrapper"
	"github.com/metacubex/mihomo/tunnel"
)

func TestBuildRuleMatchMetadata(t *testing.T) {
	metadata, err := buildRuleMatchMetadata(&RuleMatchMetadata{
		UID:               10001,
		Network:           "tcp",
		SourceIP:          "10.0.0.2",
		SourcePort:        "51000",
		DestinationIP:     "2001:db8::1",
		DestinationPort:   "443",
		Host:              "Api.Example.com.",
		Process:           "com.example.app",
		ProcessPath:       "/data/app/com.example.app/base.apk",
		SourceGeoIP:       []string{"CN"},
		DestinationGeoIP:  []string{"US"},
		SourceIPASN:       "4134",
		DestinationIPASN:  "13335",
		RemoteDestination: "api.example.com:443",
	})
	if err != nil {
		t.Fatalf("buildRuleMatchMetadata: %v", err)
	}
	if metadata.NetWork != C.TCP {
		t.Fatalf("network = %s, want tcp", metadata.NetWork)
	}
	if got := metadata.SrcIP.String(); got != "10.0.0.2" {
		t.Fatalf("source IP = %q", got)
	}
	if got := metadata.DstIP.String(); got != "2001:db8::1" {
		t.Fatalf("destination IP = %q", got)
	}
	if metadata.SrcPort != 51000 || metadata.DstPort != 443 {
		t.Fatalf("ports = %d -> %d", metadata.SrcPort, metadata.DstPort)
	}
	if metadata.Host != "Api.Example.com" {
		t.Fatalf("host = %q, want trailing dot removed", metadata.Host)
	}
	if metadata.Uid != 10001 || metadata.Process != "com.example.app" {
		t.Fatalf("process identity was not preserved: %#v", metadata)
	}
}

func TestHandleRuleMatchUsesCompiledOrderWithoutChangingStatistics(t *testing.T) {
	previousMode := tunnel.Mode()
	previousRules := append([]C.Rule(nil), tunnel.Rules()...)
	previousProxies := tunnel.Proxies()
	previousProviders := tunnel.ProvidersSnapshot()
	previousRuleProviders := tunnel.RuleProvidersSnapshot()
	t.Cleanup(func() {
		tunnel.SetMode(previousMode)
		tunnel.UpdateRules(previousRules, nil, previousRuleProviders)
		tunnel.UpdateProxies(previousProxies, previousProviders)
	})

	domainRule, err := R.ParseRule(
		"DOMAIN-SUFFIX",
		"example.com",
		"Proxy",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("parse domain rule: %v", err)
	}
	fallbackRule, err := R.ParseRule("MATCH", "", "DIRECT", nil, nil)
	if err != nil {
		t.Fatalf("parse fallback rule: %v", err)
	}
	wrapped := RW.NewRuleWrapper(domainRule)
	tunnel.UpdateRules([]C.Rule{wrapped, fallbackRule}, nil, nil)
	tunnel.UpdateProxies(map[string]C.Proxy{
		"Proxy":  namedProxy("Proxy"),
		"DIRECT": namedProxy("DIRECT"),
	}, nil)
	tunnel.SetMode(tunnel.Rule)

	result, methodErr := handleRuleMatch(&RuleMatchMetadata{
		Network:         "tcp",
		Host:            "api.example.com",
		DestinationPort: "443",
	})
	if methodErr != nil {
		t.Fatalf("handleRuleMatch: %v", methodErr)
	}
	if !result.Matched {
		t.Fatal("compiled rule did not match")
	}
	if result.RuleIndex != 0 {
		t.Fatalf("rule index = %d, want 0", result.RuleIndex)
	}
	if result.RuleType != "DomainSuffix" || result.Payload != "example.com" {
		t.Fatalf("matched rule = %s(%s)", result.RuleType, result.Payload)
	}
	if result.Target != "Proxy" {
		t.Fatalf("target = %q, want Proxy", result.Target)
	}
	if wrapped.HitCount() != 0 || wrapped.MissCount() != 0 {
		t.Fatalf(
			"diagnostic probe changed rule statistics: hit=%d miss=%d",
			wrapped.HitCount(),
			wrapped.MissCount(),
		)
	}
}

func TestHandleRuleMatchReportsDirectModeWithoutScanningRules(t *testing.T) {
	previousMode := tunnel.Mode()
	t.Cleanup(func() { tunnel.SetMode(previousMode) })
	tunnel.SetMode(tunnel.Direct)

	result, methodErr := handleRuleMatch(&RuleMatchMetadata{
		Network:         "udp",
		DestinationIP:   "1.1.1.1",
		DestinationPort: "53",
	})
	if methodErr != nil {
		t.Fatalf("handleRuleMatch: %v", methodErr)
	}
	if result.Mode != "direct" || result.Target != "DIRECT" {
		t.Fatalf("direct result = %#v", result)
	}
	if result.Matched || result.RuleIndex != -1 {
		t.Fatalf("direct mode should not report a rule: %#v", result)
	}
}

func TestMatchRuleMethodIsRegistered(t *testing.T) {
	if _, exists := methodHandlers[matchRuleMethod]; !exists {
		t.Fatal("matchRule core method is not registered")
	}
}
