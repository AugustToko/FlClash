package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v3"
)

const (
	explainPolicyMethod CoreMethod = "explainPolicy"
	policyHashMaxRetry             = 5
)

type PolicyExplainParams struct {
	Target      string            `json:"target"`
	PolicyChain []string          `json:"policyChain"`
	Metadata    RuleMatchMetadata `json:"metadata"`
}

type PolicyExplainStep struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	Selected       string `json:"selected"`
	Reason         string `json:"reason"`
	Strategy       string `json:"strategy"`
	Key            string `json:"key"`
	KeySource      string `json:"keySource"`
	TestURL        string `json:"testURL"`
	Fastest        string `json:"fastest"`
	CandidateCount int    `json:"candidateCount"`
	SelectedIndex  int    `json:"selectedIndex"`
	Bucket         int    `json:"bucket"`
	Retry          int    `json:"retry"`
	Tolerance      uint16 `json:"tolerance"`
	SelectedDelay  uint16 `json:"selectedDelay"`
	FastestDelay   uint16 `json:"fastestDelay"`
	Fixed          bool   `json:"fixed"`
	HealthKnown    bool   `json:"healthKnown"`
	SelectedAlive  bool   `json:"selectedAlive"`
	Complete       bool   `json:"complete"`
}

type PolicyExplainResult struct {
	Target      string              `json:"target"`
	PolicyChain []string            `json:"policyChain"`
	Steps       []PolicyExplainStep `json:"steps"`
	Complete    bool                `json:"complete"`
	Warnings    []string            `json:"warnings"`
}

type policyGroupDescriptor struct {
	Name      string `yaml:"name"`
	Type      string `yaml:"type"`
	Strategy  string `yaml:"strategy"`
	URL       string `yaml:"url"`
	Tolerance uint16 `yaml:"tolerance"`
}

type policyConfigDescriptor struct {
	ProxyGroups []policyGroupDescriptor `yaml:"proxy-groups"`
}

type policyRuntimeGroupState struct {
	Now       string `json:"now"`
	Fixed     string `json:"fixed"`
	TestURL   string `json:"testUrl"`
	Available bool   `json:"-"`
}

type policyProxyGroup interface {
	Proxies() []C.Proxy
}

type policyCandidateSnapshot struct {
	Name        string
	Alive       bool
	Delay       uint16
	HealthKnown bool
}

func newPolicyExplainResult(params *PolicyExplainParams) *PolicyExplainResult {
	return &PolicyExplainResult{
		Target:      strings.TrimSpace(params.Target),
		PolicyChain: normalizePolicyExplainChain(params.PolicyChain),
		Steps:       []PolicyExplainStep{},
		Complete:    true,
		Warnings:    []string{},
	}
}

func (result *PolicyExplainResult) addWarning(value string) {
	if value == "" {
		return
	}
	for _, warning := range result.Warnings {
		if warning == value {
			return
		}
	}
	result.Warnings = append(result.Warnings, value)
	result.Complete = false
}

func normalizePolicyExplainChain(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func loadPolicyGroupDescriptors() (map[string]policyGroupDescriptor, error) {
	data, err := os.ReadFile(filepath.Join(C.Path.HomeDir(), "config.yaml"))
	if err != nil {
		return nil, err
	}
	var raw policyConfigDescriptor
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	result := make(map[string]policyGroupDescriptor, len(raw.ProxyGroups))
	for _, descriptor := range raw.ProxyGroups {
		name := strings.TrimSpace(descriptor.Name)
		if name == "" {
			continue
		}
		descriptor.Name = name
		descriptor.Type = strings.ToLower(strings.TrimSpace(descriptor.Type))
		descriptor.Strategy = strings.ToLower(strings.TrimSpace(descriptor.Strategy))
		descriptor.URL = strings.TrimSpace(descriptor.URL)
		result[name] = descriptor
	}
	return result, nil
}

func snapshotPolicyExplainProxies() map[string]C.Proxy {
	configMu.Lock()
	defer configMu.Unlock()

	var source map[string]C.Proxy
	if currentConfig != nil && len(currentConfig.Proxies) > 0 {
		source = currentConfig.Proxies
	} else {
		source = tunnel.AllProxies()
	}
	result := make(map[string]C.Proxy, len(source))
	for name, proxy := range source {
		result[name] = proxy
	}
	return result
}

func policyGroupNow(adapter C.ProxyAdapter) (now string) {
	group, ok := adapter.(interface{ Now() string })
	if !ok {
		return ""
	}
	defer func() {
		if recover() != nil {
			now = ""
		}
	}()
	return group.Now()
}

func policyRuntimeState(proxy C.Proxy) (state policyRuntimeGroupState) {
	if proxy == nil {
		return state
	}
	adapter := proxy.Adapter()
	state.Now = policyGroupNow(adapter)

	// Selector only needs its current member, and load-balance state comes from
	// its descriptor plus the authoritative matched chain. Avoid MarshalJSON for
	// these groups: dashboard serialization also touches decorative fields such
	// as emptyFallback and is not a safe diagnostics API for partially loaded or
	// test-created groups.
	if proxy.Type() == C.Selector || proxy.Type() == C.LoadBalance {
		state.Available = true
		return state
	}

	defer func() {
		if recover() != nil {
			state.Available = false
		}
	}()
	data, err := adapter.MarshalJSON()
	if err != nil {
		return state
	}
	decoded := policyRuntimeGroupState{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return state
	}
	if decoded.Now == "" {
		decoded.Now = state.Now
	}
	decoded.Available = true
	return decoded
}

func policyCandidateStates(
	proxies []C.Proxy,
	testURL string,
) []policyCandidateSnapshot {
	states := make([]policyCandidateSnapshot, 0, len(proxies))
	for _, proxy := range proxies {
		state := policyCandidateSnapshot{
			Name:  proxy.Name(),
			Alive: proxy.AliveForTestUrl(testURL),
			Delay: proxy.LastDelayForTestUrl(testURL),
		}
		if history, exists := proxy.ExtraDelayHistories()[testURL]; exists {
			state.HealthKnown = len(history.History) > 0
		} else {
			state.HealthKnown = len(proxy.DelayHistory()) > 0
		}
		states = append(states, state)
	}
	return states
}

func findPolicyCandidate(
	candidates []policyCandidateSnapshot,
	name string,
) (policyCandidateSnapshot, int, bool) {
	for index, candidate := range candidates {
		if candidate.Name == name {
			return candidate, index, true
		}
	}
	return policyCandidateSnapshot{}, -1, false
}

func policyDestinationKey(metadata *C.Metadata) (key string, source string) {
	if metadata != nil && metadata.Host != "" {
		if net.ParseIP(metadata.Host) != nil {
			return metadata.Host, "host-ip"
		}
		if etld, err := publicsuffix.EffectiveTLDPlusOne(metadata.Host); err == nil {
			return etld, "etld+1"
		}
	}
	if metadata != nil && metadata.DstIP.IsValid() {
		return metadata.DstIP.String(), "destination-ip"
	}
	return "", "empty"
}

func policyStickyKey(metadata *C.Metadata) (key string, source string) {
	destination, destinationSource := policyDestinationKey(metadata)
	sourceIP := ""
	if metadata != nil {
		sourceIP = metadata.SrcIP.String()
	}
	return sourceIP + destination, "source-ip+" + destinationSource
}

func policyJumpHash(key uint64, buckets int32) int32 {
	var bucket, next int64
	for next < int64(buckets) {
		bucket = next
		key = key*2862933555777941757 + 1
		next = int64(float64(bucket+1) * (float64(int64(1)<<31) / float64((key>>33)+1)))
	}
	return int32(bucket)
}

func predictPolicyConsistentHash(
	candidates []policyCandidateSnapshot,
	key string,
) (selected int, bucket int, retry int) {
	if len(candidates) == 0 {
		return -1, -1, -1
	}
	hash := utils.MapHash(key)
	buckets := int32(len(candidates))
	for attempt := 0; attempt < policyHashMaxRetry; attempt, hash = attempt+1, hash+1 {
		index := int(policyJumpHash(hash, buckets))
		if candidates[index].Alive {
			return index, index, attempt
		}
	}
	for index, candidate := range candidates {
		if candidate.Alive {
			return index, index, policyHashMaxRetry
		}
	}
	return 0, 0, policyHashMaxRetry
}

func fastestPolicyCandidate(
	candidates []policyCandidateSnapshot,
) (policyCandidateSnapshot, int, bool) {
	if len(candidates) == 0 {
		return policyCandidateSnapshot{}, -1, false
	}
	fastest := candidates[0]
	fastestIndex := 0
	for index := 1; index < len(candidates); index++ {
		candidate := candidates[index]
		if candidate.Alive && candidate.Delay < fastest.Delay {
			fastest = candidate
			fastestIndex = index
		}
	}
	return fastest, fastestIndex, true
}

func firstAlivePolicyCandidate(
	candidates []policyCandidateSnapshot,
) (policyCandidateSnapshot, int, bool) {
	for index, candidate := range candidates {
		if candidate.Alive {
			return candidate, index, true
		}
	}
	if len(candidates) == 0 {
		return policyCandidateSnapshot{}, -1, false
	}
	return candidates[0], 0, false
}

func basePolicyExplainStep(
	proxy C.Proxy,
	selected string,
	candidates []policyCandidateSnapshot,
) PolicyExplainStep {
	step := PolicyExplainStep{
		Name:           proxy.Name(),
		Type:           proxy.Type().String(),
		Selected:       selected,
		CandidateCount: len(candidates),
		SelectedIndex:  -1,
		Bucket:         -1,
		Retry:          -1,
		Complete:       true,
	}
	if selected == "" {
		step.Reason = "leaf"
		return step
	}
	candidate, index, exists := findPolicyCandidate(candidates, selected)
	if !exists {
		step.Reason = "selected-member-unavailable"
		step.Complete = false
		return step
	}
	step.SelectedIndex = index
	step.SelectedAlive = candidate.Alive
	step.SelectedDelay = candidate.Delay
	step.HealthKnown = candidate.HealthKnown
	return step
}

func explainSelectorPolicy(
	step *PolicyExplainStep,
	state policyRuntimeGroupState,
) {
	step.Reason = "manual-selection"
	if step.SelectedIndex < 0 {
		step.Complete = false
		return
	}
	if state.Now != "" && state.Now != step.Selected {
		step.Reason = "manual-selection-state-changed"
		step.Complete = false
	}
}

func explainFallbackPolicy(
	step *PolicyExplainStep,
	state policyRuntimeGroupState,
	candidates []policyCandidateSnapshot,
) {
	step.TestURL = state.TestURL
	step.Fixed = state.Fixed != ""
	if step.SelectedIndex < 0 {
		step.Reason = "selected-member-unavailable"
		step.Complete = false
		return
	}
	if state.Fixed != "" {
		if state.Fixed == step.Selected && step.SelectedAlive {
			step.Reason = "fixed-selection"
			return
		}
		step.Reason = "fixed-unavailable-fallback"
		step.Complete = false
		return
	}
	expected, expectedIndex, anyAlive := firstAlivePolicyCandidate(candidates)
	if anyAlive {
		step.Reason = "first-alive"
	} else {
		step.Reason = "no-alive-first-member"
	}
	if expectedIndex < 0 || expected.Name != step.Selected {
		step.Complete = false
	}
}

func explainURLTestPolicy(
	step *PolicyExplainStep,
	state policyRuntimeGroupState,
	descriptor policyGroupDescriptor,
	candidates []policyCandidateSnapshot,
) {
	step.TestURL = state.TestURL
	step.Tolerance = descriptor.Tolerance
	step.Fixed = state.Fixed != ""
	if step.SelectedIndex < 0 {
		step.Reason = "selected-member-unavailable"
		step.Complete = false
		return
	}
	if state.Fixed != "" {
		if state.Fixed == step.Selected && step.SelectedAlive {
			step.Reason = "fixed-selection"
			return
		}
		step.Reason = "fixed-unavailable-fallback"
		step.Complete = false
		return
	}
	fastest, _, exists := fastestPolicyCandidate(candidates)
	if !exists {
		step.Reason = "no-candidates"
		step.Complete = false
		return
	}
	step.Fastest = fastest.Name
	step.FastestDelay = fastest.Delay
	if step.Selected == fastest.Name {
		step.Reason = "lowest-delay"
		return
	}
	if step.SelectedAlive && step.SelectedDelay <= fastest.Delay+step.Tolerance {
		step.Reason = "tolerance-hold"
		return
	}
	step.Reason = "cached-selection-state-changed"
	step.Complete = false
}

func explainLoadBalancePolicy(
	step *PolicyExplainStep,
	descriptor policyGroupDescriptor,
	metadata *C.Metadata,
	candidates []policyCandidateSnapshot,
) {
	step.Strategy = descriptor.Strategy
	if step.Strategy == "" {
		step.Strategy = "consistent-hashing"
	}
	if step.SelectedIndex < 0 {
		step.Reason = "selected-member-unavailable"
		step.Complete = false
		return
	}
	switch step.Strategy {
	case "consistent-hashing":
		step.Key, step.KeySource = policyDestinationKey(metadata)
		predicted, bucket, retry := predictPolicyConsistentHash(candidates, step.Key)
		step.Bucket = bucket
		step.Retry = retry
		step.Reason = "consistent-hash"
		if predicted < 0 || candidates[predicted].Name != step.Selected {
			step.Reason = "consistent-hash-state-changed"
			step.Complete = false
		}
	case "round-robin":
		step.Reason = "round-robin-current-cursor"
		step.Complete = false
	case "sticky-sessions":
		step.Key, step.KeySource = policyStickyKey(metadata)
		step.Reason = "sticky-session-cache"
		step.Complete = false
	default:
		step.Reason = "unknown-load-balance-strategy"
		step.Complete = false
	}
}

func explainPolicyChain(
	params *PolicyExplainParams,
	metadata *C.Metadata,
	proxies map[string]C.Proxy,
	descriptors map[string]policyGroupDescriptor,
	configAvailable bool,
) *PolicyExplainResult {
	result := newPolicyExplainResult(params)
	if result.Target == "" {
		result.addWarning("policy-target-empty")
		return result
	}
	if len(result.PolicyChain) == 0 {
		result.PolicyChain = []string{result.Target}
	}
	if result.PolicyChain[0] != result.Target {
		result.addWarning("policy-chain-target-mismatch")
	}

	for index, name := range result.PolicyChain {
		proxy, exists := proxies[name]
		if !exists {
			result.Steps = append(result.Steps, PolicyExplainStep{
				Name:          name,
				SelectedIndex: -1,
				Bucket:        -1,
				Retry:         -1,
				Reason:        "proxy-unavailable",
				Complete:      false,
			})
			result.addWarning("policy-proxy-unavailable")
			continue
		}

		selected := ""
		if index+1 < len(result.PolicyChain) {
			selected = result.PolicyChain[index+1]
		}
		adapter := proxy.Adapter()
		group, isGroup := adapter.(policyProxyGroup)
		if !isGroup {
			step := basePolicyExplainStep(proxy, selected, nil)
			if selected != "" {
				step.Reason = "non-group-chain-continuation"
				step.Complete = false
				result.addWarning("policy-chain-invalid-continuation")
			}
			result.Steps = append(result.Steps, step)
			if !step.Complete {
				result.Complete = false
			}
			continue
		}

		state := policyRuntimeGroupState{}
		if proxy.Type() == C.Selector ||
			proxy.Type() == C.Fallback ||
			proxy.Type() == C.URLTest ||
			proxy.Type() == C.LoadBalance {
			state = policyRuntimeState(proxy)
		}
		testURL := state.TestURL
		descriptor, descriptorExists := descriptors[name]
		if testURL == "" {
			testURL = descriptor.URL
		}
		candidates := policyCandidateStates(group.Proxies(), testURL)
		step := basePolicyExplainStep(proxy, selected, candidates)
		switch proxy.Type() {
		case C.Selector:
			explainSelectorPolicy(&step, state)
		case C.Fallback:
			if !state.Available {
				step.Complete = false
				result.addWarning("policy-runtime-state-unavailable")
			}
			explainFallbackPolicy(&step, state, candidates)
		case C.URLTest:
			if !state.Available {
				step.Complete = false
				result.addWarning("policy-runtime-state-unavailable")
			}
			descriptorValid := descriptorExists && descriptor.Type == "url-test"
			if !descriptorValid && state.Fixed == "" {
				step.Complete = false
				result.addWarning("policy-config-unavailable")
			}
			explainURLTestPolicy(&step, state, descriptor, candidates)
		case C.LoadBalance:
			if !descriptorExists || !configAvailable || descriptor.Type != "load-balance" {
				step.Reason = "load-balance-config-unavailable"
				step.Complete = false
			} else {
				explainLoadBalancePolicy(&step, descriptor, metadata, candidates)
			}
		case C.Relay:
			step.Reason = "legacy-relay-unavailable"
			step.Complete = false
		default:
			step.Reason = "unsupported-policy-group"
			step.Complete = false
		}
		result.Steps = append(result.Steps, step)
		if !step.Complete {
			result.Complete = false
		}
	}

	for _, step := range result.Steps {
		switch step.Reason {
		case "selected-member-unavailable", "proxy-unavailable":
			result.addWarning("policy-chain-member-unavailable")
		case "manual-selection-state-changed", "consistent-hash-state-changed", "cached-selection-state-changed":
			result.addWarning("policy-selection-state-changed")
		case "load-balance-config-unavailable":
			result.addWarning("policy-config-unavailable")
		case "round-robin-current-cursor", "sticky-session-cache":
			result.addWarning("policy-strategy-state-hidden")
		case "legacy-relay-unavailable":
			result.addWarning("legacy-relay-unavailable")
		}
	}
	return result
}

func handlePolicyExplain(
	params *PolicyExplainParams,
) (*PolicyExplainResult, *MethodError) {
	metadata, err := buildRuleMatchMetadata(&params.Metadata)
	if err != nil {
		return nil, &MethodError{
			Code:    "invalid_arguments",
			Message: err.Error(),
		}
	}
	descriptors, descriptorErr := loadPolicyGroupDescriptors()
	configAvailable := descriptorErr == nil
	if descriptors == nil {
		descriptors = map[string]policyGroupDescriptor{}
	}
	return explainPolicyChain(
		params,
		metadata,
		snapshotPolicyExplainProxies(),
		descriptors,
		configAvailable,
	), nil
}

func init() {
	registerMethod(explainPolicyMethod, withArguments(func(
		params *PolicyExplainParams,
		response MethodResponse,
	) {
		safeGo(response, func() {
			result, methodErr := handlePolicyExplain(params)
			if methodErr != nil {
				response.failure(
					methodErr.Code,
					methodErr.Message,
					methodErr.Details,
				)
				return
			}
			response.success(result)
		})
	}))
}
