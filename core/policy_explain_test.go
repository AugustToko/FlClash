package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"
)

func policyExplainLoadBalanceGroup(
	t *testing.T,
	name string,
	strategy string,
	members ...string,
) (C.Proxy, map[string]C.Proxy) {
	t.Helper()

	proxies := make([]C.Proxy, 0, len(members))
	mapping := make(map[string]C.Proxy, len(members)+1)
	for _, member := range members {
		proxy := namedProxy(member)
		proxies = append(proxies, proxy)
		mapping[member] = proxy
	}
	health := provider.NewHealthCheck(proxies, "", 0, 0, true, nil)
	compatible, err := provider.NewCompatibleProvider(
		name+"-provider",
		proxies,
		health,
	)
	if err != nil {
		t.Fatalf("NewCompatibleProvider: %v", err)
	}
	emptyFallback := namedProxy("COMPATIBLE")
	mapping[emptyFallback.Name()] = emptyFallback
	group, err := outboundgroup.NewLoadBalance(
		outboundgroup.GroupCommonOption{Name: name},
		outboundgroup.LoadBalanceOption{Strategy: strategy},
		emptyFallback,
		[]P.ProxyProvider{compatible},
	)
	if err != nil {
		t.Fatalf("NewLoadBalance: %v", err)
	}
	wrapped := adapter.NewProxy(group)
	mapping[name] = wrapped
	return wrapped, mapping
}

func policyExplainComputedGroup(
	t *testing.T,
	groupType string,
	name string,
	fixed string,
	members ...string,
) (C.Proxy, map[string]C.Proxy) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	proxies := make([]C.Proxy, 0, len(members))
	mapping := make(map[string]C.Proxy, len(members)+2)
	for _, member := range members {
		proxy := namedProxy(member)
		proxies = append(proxies, proxy)
		mapping[member] = proxy
	}

	aliveMember := fixed
	if aliveMember == "" && len(members) > 0 {
		aliveMember = members[0]
	}
	aliveProxy := mapping[aliveMember]
	if aliveProxy == nil {
		t.Fatalf("alive test member %q is unavailable", aliveMember)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := aliveProxy.URLTest(ctx, server.URL, nil); err != nil {
		t.Fatalf("seed %s health state: %v", aliveMember, err)
	}

	health := provider.NewHealthCheck(proxies, server.URL, 0, 0, true, nil)
	compatible, err := provider.NewCompatibleProvider(
		name+"-provider",
		proxies,
		health,
	)
	if err != nil {
		t.Fatalf("NewCompatibleProvider: %v", err)
	}
	emptyFallback := namedProxy("COMPATIBLE")
	mapping[emptyFallback.Name()] = emptyFallback
	common := outboundgroup.GroupCommonOption{
		Name: name,
		URL:  server.URL,
	}
	var group C.ProxyAdapter
	switch groupType {
	case "fallback":
		typed, newErr := outboundgroup.NewFallback(
			common,
			outboundgroup.FallbackOption{},
			emptyFallback,
			[]P.ProxyProvider{compatible},
		)
		if newErr != nil {
			t.Fatalf("NewFallback: %v", newErr)
		}
		if fixed != "" {
			typed.ForceSet(fixed)
		}
		group = typed
	case "url-test":
		typed, newErr := outboundgroup.NewURLTest(
			common,
			outboundgroup.URLTestOption{Tolerance: 50},
			emptyFallback,
			[]P.ProxyProvider{compatible},
		)
		if newErr != nil {
			t.Fatalf("NewURLTest: %v", newErr)
		}
		if fixed != "" {
			typed.ForceSet(fixed)
		}
		group = typed
	default:
		t.Fatalf("unsupported computed group type %q", groupType)
	}
	wrapped := adapter.NewProxy(group)
	mapping[name] = wrapped
	return wrapped, mapping
}

func TestPolicyDestinationKeyMatchesMihomo(t *testing.T) {
	tests := []struct {
		name       string
		metadata   *C.Metadata
		wantKey    string
		wantSource string
	}{
		{
			name:       "effective tld plus one",
			metadata:   &C.Metadata{Host: "api.example.co.uk"},
			wantKey:    "example.co.uk",
			wantSource: "etld+1",
		},
		{
			name:       "literal host ip",
			metadata:   &C.Metadata{Host: "2001:db8::1"},
			wantKey:    "2001:db8::1",
			wantSource: "host-ip",
		},
		{
			name: "destination ip fallback",
			metadata: &C.Metadata{
				Host:  "localhost",
				DstIP: netip.MustParseAddr("1.1.1.1"),
			},
			wantKey:    "1.1.1.1",
			wantSource: "destination-ip",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, source := policyDestinationKey(test.metadata)
			if key != test.wantKey || source != test.wantSource {
				t.Fatalf(
					"policyDestinationKey = %q/%q, want %q/%q",
					key,
					source,
					test.wantKey,
					test.wantSource,
				)
			}
		})
	}
}

func TestPredictPolicyConsistentHashRetriesDeadBuckets(t *testing.T) {
	key := "example.com"
	candidates := []policyCandidateSnapshot{
		{Name: "a", Alive: false},
		{Name: "b", Alive: false},
		{Name: "c", Alive: false},
	}
	first, _, _ := predictPolicyConsistentHash(candidates, key)
	if first != 0 {
		t.Fatalf("all-dead fallback = %d, want first member", first)
	}

	firstBucket := int(policyJumpHash(
		policyMapHashForTest(key),
		int32(len(candidates)),
	))
	aliveIndex := (firstBucket + 1) % len(candidates)
	candidates[aliveIndex].Alive = true
	selected, bucket, retry := predictPolicyConsistentHash(candidates, key)
	if selected != aliveIndex || bucket != aliveIndex {
		t.Fatalf(
			"consistent hash selected %d/bucket %d, want alive member %d",
			selected,
			bucket,
			aliveIndex,
		)
	}
	if retry < 0 || retry > policyHashMaxRetry {
		t.Fatalf("retry = %d, want a bounded retry/fallback value", retry)
	}
}

func policyMapHashForTest(value string) uint64 {
	// Keep the test independent from a hard-coded hash value while using the
	// same public helper the pinned Mihomo strategy calls.
	return utils.MapHash(value)
}

func TestExplainPolicyChainDescribesSelectorAndLeaf(t *testing.T) {
	group := selectorGroup(t, "Proxy", "node-a", "node-b")
	proxies := map[string]C.Proxy{
		"Proxy":  group,
		"node-a": namedProxy("node-a"),
		"node-b": namedProxy("node-b"),
	}
	result := explainPolicyChain(
		&PolicyExplainParams{
			Target:      "Proxy",
			PolicyChain: []string{"Proxy", "node-a"},
		},
		&C.Metadata{},
		proxies,
		nil,
		false,
	)
	if !result.Complete || len(result.Warnings) != 0 {
		t.Fatalf("selector explanation is incomplete: %#v", result)
	}
	if len(result.Steps) != 2 {
		t.Fatalf("steps = %d, want group and leaf", len(result.Steps))
	}
	if result.Steps[0].Reason != "manual-selection" ||
		result.Steps[0].Selected != "node-a" ||
		result.Steps[0].SelectedIndex != 0 {
		t.Fatalf("selector step = %#v", result.Steps[0])
	}
	if result.Steps[1].Reason != "leaf" || !result.Steps[1].Complete {
		t.Fatalf("leaf step = %#v", result.Steps[1])
	}
}

func TestExplainPolicyChainDetectsSelectorStateChanges(t *testing.T) {
	group := selectorGroup(t, "Proxy", "node-a", "node-b")
	proxies := map[string]C.Proxy{
		"Proxy":  group,
		"node-a": namedProxy("node-a"),
		"node-b": namedProxy("node-b"),
	}
	result := explainPolicyChain(
		&PolicyExplainParams{
			Target:      "Proxy",
			PolicyChain: []string{"Proxy", "node-b"},
		},
		&C.Metadata{},
		proxies,
		nil,
		false,
	)
	if result.Complete || !containsRuleMatchWarning(
		result.Warnings,
		"policy-selection-state-changed",
	) {
		t.Fatalf("selector state change = %#v", result)
	}
	if result.Steps[0].Reason != "manual-selection-state-changed" {
		t.Fatalf("selector step = %#v", result.Steps[0])
	}
}

func TestExplainPolicyChainDescribesComputedGroups(t *testing.T) {
	tests := []struct {
		groupType string
		fixed     string
		selected  string
		reason    string
	}{
		{groupType: "fallback", selected: "node-a", reason: "first-alive"},
		{groupType: "fallback", fixed: "node-b", selected: "node-b", reason: "fixed-selection"},
		{groupType: "url-test", selected: "node-a", reason: "lowest-delay"},
		{groupType: "url-test", fixed: "node-b", selected: "node-b", reason: "fixed-selection"},
	}
	for _, test := range tests {
		name := test.groupType + "-" + test.reason
		t.Run(name, func(t *testing.T) {
			_, proxies := policyExplainComputedGroup(
				t,
				test.groupType,
				"Computed",
				test.fixed,
				"node-a",
				"node-b",
			)
			descriptors := map[string]policyGroupDescriptor{}
			if test.groupType == "url-test" && test.fixed == "" {
				descriptors["Computed"] = policyGroupDescriptor{
					Name:      "Computed",
					Type:      "url-test",
					Tolerance: 50,
				}
			}
			result := explainPolicyChain(
				&PolicyExplainParams{
					Target:      "Computed",
					PolicyChain: []string{"Computed", test.selected},
				},
				&C.Metadata{},
				proxies,
				descriptors,
				true,
			)
			if !result.Complete || len(result.Warnings) != 0 {
				t.Fatalf("computed explanation = %#v", result)
			}
			step := result.Steps[0]
			if step.Reason != test.reason || step.Selected != test.selected {
				t.Fatalf("computed step = %#v", step)
			}
			if step.Fixed != (test.fixed != "") {
				t.Fatalf("fixed = %v, want %v", step.Fixed, test.fixed != "")
			}
			if !step.HealthKnown || !step.SelectedAlive {
				t.Fatalf("seeded health state was lost: %#v", step)
			}
		})
	}
}

func TestSnapshotPolicyExplainProxiesFallsBackToTunnel(t *testing.T) {
	withCurrentConfig(t, &config.Config{Proxies: map[string]C.Proxy{}})
	tunnelProxy := namedProxy("tunnel-node")
	tunnel.UpdateProxies(map[string]C.Proxy{"tunnel-node": tunnelProxy}, nil)
	t.Cleanup(func() { tunnel.UpdateProxies(nil, nil) })

	snapshot := snapshotPolicyExplainProxies()
	if snapshot["tunnel-node"] != tunnelProxy {
		t.Fatalf("snapshot = %#v, want tunnel fallback", snapshot)
	}
}

func TestExplainPolicyChainReproducesConsistentHashing(t *testing.T) {
	group, proxies := policyExplainLoadBalanceGroup(
		t,
		"Balance",
		"consistent-hashing",
		"node-a",
		"node-b",
		"node-c",
	)
	metadata := &C.Metadata{Host: "api.example.com"}
	selected := group.Unwrap(metadata, false)
	if selected == nil {
		t.Fatal("load-balance group selected no member")
	}
	result := explainPolicyChain(
		&PolicyExplainParams{
			Target:      "Balance",
			PolicyChain: []string{"Balance", selected.Name()},
		},
		metadata,
		proxies,
		map[string]policyGroupDescriptor{
			"Balance": {
				Name:     "Balance",
				Type:     "load-balance",
				Strategy: "consistent-hashing",
			},
		},
		true,
	)
	if !result.Complete || len(result.Warnings) != 0 {
		t.Fatalf("consistent-hash explanation = %#v", result)
	}
	step := result.Steps[0]
	if step.Reason != "consistent-hash" ||
		step.Key != "example.com" ||
		step.KeySource != "etld+1" ||
		step.Bucket < 0 ||
		step.Retry < 0 {
		t.Fatalf("consistent-hash step = %#v", step)
	}
}

func TestExplainPolicyChainMarksHiddenLoadBalanceState(t *testing.T) {
	for _, strategy := range []string{"round-robin", "sticky-sessions"} {
		t.Run(strategy, func(t *testing.T) {
			group, proxies := policyExplainLoadBalanceGroup(
				t,
				"Balance",
				strategy,
				"node-a",
				"node-b",
			)
			metadata := &C.Metadata{
				Host:  "api.example.com",
				SrcIP: netip.MustParseAddr("10.0.0.2"),
			}
			selected := group.Unwrap(metadata, false)
			result := explainPolicyChain(
				&PolicyExplainParams{
					Target:      "Balance",
					PolicyChain: []string{"Balance", selected.Name()},
				},
				metadata,
				proxies,
				map[string]policyGroupDescriptor{
					"Balance": {
						Name:     "Balance",
						Type:     "load-balance",
						Strategy: strategy,
					},
				},
				true,
			)
			if result.Complete || !containsRuleMatchWarning(
				result.Warnings,
				"policy-strategy-state-hidden",
			) {
				t.Fatalf("%s explanation = %#v", strategy, result)
			}
			step := result.Steps[0]
			if !strings.HasPrefix(step.Reason, strings.Split(strategy, "-")[0]) {
				t.Fatalf("%s reason = %q", strategy, step.Reason)
			}
			if strategy == "sticky-sessions" && step.Key == "" {
				t.Fatal("sticky-session explanation omitted its stable cache key")
			}
		})
	}
}

func TestExplainPolicyMethodIsRegistered(t *testing.T) {
	if _, exists := methodHandlers[explainPolicyMethod]; !exists {
		t.Fatal("explainPolicy core method is not registered")
	}
}
