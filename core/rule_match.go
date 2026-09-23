package main

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/metacubex/mihomo/tunnel"
)

const (
	matchRuleMethod         CoreMethod = "matchRule"
	maxRuleMatchPolicyDepth            = 64
)

type RuleMatchMetadata struct {
	UID               uint32   `json:"uid"`
	Network           string   `json:"network"`
	SourceIP          string   `json:"sourceIP"`
	SourcePort        string   `json:"sourcePort"`
	DestinationIP     string   `json:"destinationIP"`
	DestinationPort   string   `json:"destinationPort"`
	Host              string   `json:"host"`
	Process           string   `json:"process"`
	ProcessPath       string   `json:"processPath"`
	RemoteDestination string   `json:"remoteDestination"`
	SourceGeoIP       []string `json:"sourceGeoIP"`
	DestinationGeoIP  []string `json:"destinationGeoIP"`
	DestinationIPASN  string   `json:"destinationIPASN"`
	SourceIPASN       string   `json:"sourceIPASN"`
	SpecialRules      string   `json:"specialRules"`
	SpecialProxy      string   `json:"specialProxy"`
	InboundIP         string   `json:"inboundIP"`
	InboundPort       string   `json:"inboundPort"`
	InboundName       string   `json:"inboundName"`
	InboundUser       string   `json:"inboundUser"`
	InboundType       string   `json:"inboundType"`
	RematchName       string   `json:"rematchName"`
	DSCP              *uint8   `json:"dscp"`
}

type RuleMatchResult struct {
	Mode          string   `json:"mode"`
	Matched       bool     `json:"matched"`
	RuleIndex     int      `json:"ruleIndex"`
	RuleType      string   `json:"ruleType"`
	Payload       string   `json:"payload"`
	Target        string   `json:"target"`
	PolicyChain   []string `json:"policyChain"`
	ProviderNames []string `json:"providerNames"`
	ResolvedIP    string   `json:"resolvedIP"`
	Complete      bool     `json:"complete"`
	Warnings      []string `json:"warnings"`
}

func newRuleMatchResult() *RuleMatchResult {
	return &RuleMatchResult{
		Mode:          "rule",
		RuleIndex:     -1,
		PolicyChain:   []string{},
		ProviderNames: []string{},
		Warnings:      []string{},
		Complete:      true,
	}
}

func (result *RuleMatchResult) addWarning(value string) {
	for _, warning := range result.Warnings {
		if warning == value {
			return
		}
	}
	result.Warnings = append(result.Warnings, value)
	result.Complete = false
}

func parseRuleMatchNetwork(value string) (C.NetWork, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "tcp":
		return C.TCP, nil
	case "udp":
		return C.UDP, nil
	case "all":
		return C.ALLNet, nil
	default:
		return C.InvalidNet, fmt.Errorf("unsupported network %q", value)
	}
}

func parseRuleMatchPort(value string) (uint16, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	return uint16(port), nil
}

func parseRuleMatchIP(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP %q", value)
	}
	return address.Unmap(), nil
}

func buildRuleMatchMetadata(params *RuleMatchMetadata) (*C.Metadata, error) {
	network, err := parseRuleMatchNetwork(params.Network)
	if err != nil {
		return nil, err
	}
	sourceIP, err := parseRuleMatchIP(params.SourceIP)
	if err != nil {
		return nil, err
	}
	destinationIP, err := parseRuleMatchIP(params.DestinationIP)
	if err != nil {
		return nil, err
	}
	inboundIP, err := parseRuleMatchIP(params.InboundIP)
	if err != nil {
		return nil, err
	}
	sourcePort, err := parseRuleMatchPort(params.SourcePort)
	if err != nil {
		return nil, err
	}
	destinationPort, err := parseRuleMatchPort(params.DestinationPort)
	if err != nil {
		return nil, err
	}
	inboundPort, err := parseRuleMatchPort(params.InboundPort)
	if err != nil {
		return nil, err
	}

	inboundType := C.Type(0)
	if value := strings.TrimSpace(params.InboundType); value != "" {
		parsed, parseErr := C.ParseType(strings.ToUpper(value))
		if parseErr != nil {
			return nil, parseErr
		}
		inboundType = *parsed
	}

	metadata := &C.Metadata{
		NetWork:      network,
		Type:         inboundType,
		SrcIP:        sourceIP,
		DstIP:        destinationIP,
		SrcPort:      sourcePort,
		DstPort:      destinationPort,
		InIP:         inboundIP,
		InPort:       inboundPort,
		InName:       params.InboundName,
		InUser:       params.InboundUser,
		RematchName:  params.RematchName,
		Host:         strings.TrimSuffix(strings.TrimSpace(params.Host), "."),
		Uid:          params.UID,
		Process:      params.Process,
		ProcessPath:  params.ProcessPath,
		SpecialProxy: params.SpecialProxy,
		SpecialRules: params.SpecialRules,
		RemoteDst:    params.RemoteDestination,
		SrcIPASN:     params.SourceIPASN,
		DstIPASN:     params.DestinationIPASN,
	}
	if len(params.SourceGeoIP) > 0 {
		metadata.SrcGeoIP = append([]string(nil), params.SourceGeoIP...)
	}
	if len(params.DestinationGeoIP) > 0 {
		metadata.DstGeoIP = append([]string(nil), params.DestinationGeoIP...)
	}
	if params.DSCP != nil {
		metadata.DSCP = *params.DSCP
	}
	return metadata, nil
}

func unwrapRuleForMatchProbe(rule C.Rule) (C.Rule, bool) {
	wrapped, ok := rule.(C.RuleWrapper)
	if !ok {
		return rule, true
	}
	if wrapped.IsDisabled() {
		return nil, false
	}
	return wrapped.Unwrap(), true
}

func missingRuleMatchField(
	ruleType C.RuleType,
	params *RuleMatchMetadata,
) string {
	switch ruleType {
	case C.InPort:
		if strings.TrimSpace(params.InboundPort) == "" {
			return "missing-inbound-port"
		}
	case C.InName:
		if strings.TrimSpace(params.InboundName) == "" {
			return "missing-inbound-name"
		}
	case C.InUser:
		if strings.TrimSpace(params.InboundUser) == "" {
			return "missing-inbound-user"
		}
	case C.InType:
		if strings.TrimSpace(params.InboundType) == "" {
			return "missing-inbound-type"
		}
	case C.DSCP:
		if params.DSCP == nil {
			return "missing-dscp"
		}
	case C.SubRules:
		return "sub-rule-context-unavailable"
	}
	return ""
}

func processRuleMatchMetadata(metadata *C.Metadata, result *RuleMatchResult) {
	if metadata.Process != "" || metadata.ProcessPath != "" || metadata.Uid != 0 {
		return
	}
	if !metadata.SrcIP.IsValid() || metadata.SrcPort == 0 {
		result.addWarning("process-lookup-source-unavailable")
		return
	}
	if features.Android {
		packageName, err := process.FindPackageName(metadata)
		if err != nil {
			result.addWarning("process-lookup-failed")
			return
		}
		metadata.Process = packageName
		return
	}
	uid, path, err := process.FindProcessName(
		metadata.NetWork.String(),
		metadata.SrcIP,
		int(metadata.SrcPort),
	)
	if err != nil {
		result.addWarning("process-lookup-failed")
		return
	}
	metadata.Uid = uid
	metadata.ProcessPath = path
	metadata.Process = filepath.Base(path)
	if packageName, packageErr := process.FindPackageName(metadata); packageErr == nil {
		metadata.Process = packageName
	}
}

func resolveRuleMatchMetadata(metadata *C.Metadata, result *RuleMatchResult) {
	if metadata.DstIP.IsValid() || metadata.Host == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
	defer cancel()
	address, err := resolver.ResolveIP(ctx, metadata.Host)
	if err != nil {
		result.addWarning("dns-resolution-failed")
		return
	}
	metadata.DstIP = address.Unmap()
}

func ruleMatchProxyIdentity(proxy C.Proxy) string {
	return fmt.Sprintf("%s\x00%d", proxy.Name(), proxy.Type())
}

func proxyTypeMayContainPolicy(typeOf C.AdapterType) bool {
	switch typeOf {
	case C.Relay, C.Selector, C.Fallback, C.URLTest, C.LoadBalance:
		return true
	default:
		return false
	}
}

func matchProbePassTarget(
	adapterName string,
	metadata *C.Metadata,
	proxies map[string]C.Proxy,
) bool {
	adapter, ok := proxies[adapterName]
	if !ok {
		return false
	}
	seen := make(map[string]struct{})
	for depth, current := 0, adapter; current != nil; depth++ {
		if depth >= maxRuleMatchPolicyDepth {
			return false
		}
		identity := ruleMatchProxyIdentity(current)
		if _, exists := seen[identity]; exists {
			return false
		}
		seen[identity] = struct{}{}
		if current.Type() == C.PassRule {
			return true
		}
		current = current.Unwrap(metadata, false)
	}
	return false
}

func traceRuleMatchPolicy(
	adapter C.Proxy,
	metadata *C.Metadata,
) (chain []string, skip bool, rematch bool, warning string) {
	chain = make([]string, 0, 4)
	seen := make(map[string]struct{})
	for depth, current := 0, adapter; current != nil; depth++ {
		if depth >= maxRuleMatchPolicyDepth {
			return chain, false, false, "policy-chain-truncated"
		}
		identity := ruleMatchProxyIdentity(current)
		if _, exists := seen[identity]; exists {
			return chain, false, false, "policy-chain-cycle"
		}
		seen[identity] = struct{}{}
		if name := strings.TrimSpace(current.Name()); name != "" &&
			(len(chain) == 0 || chain[len(chain)-1] != name) {
			chain = append(chain, name)
		}
		switch current.Type() {
		case C.Pass:
			return chain, true, false, ""
		case C.Rematch:
			return chain, false, true, ""
		}
		next := current.Unwrap(metadata, false)
		if next == nil && proxyTypeMayContainPolicy(current.Type()) {
			return chain, false, false, "policy-chain-unresolved"
		}
		current = next
	}
	return chain, false, false, ""
}

func applyRuleMatchPolicyChain(
	result *RuleMatchResult,
	target string,
	metadata *C.Metadata,
	proxies map[string]C.Proxy,
) (skip bool, rematch bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return false, false
	}
	adapter, exists := proxies[target]
	if !exists {
		result.PolicyChain = []string{target}
		return false, false
	}
	chain, skip, rematch, warning := traceRuleMatchPolicy(adapter, metadata)
	if len(chain) == 0 {
		chain = []string{target}
	}
	result.PolicyChain = chain
	if warning != "" {
		result.addWarning(warning)
	}
	return skip, rematch
}

func evaluateRuleMatch(
	params *RuleMatchMetadata,
	mode tunnel.TunnelMode,
	rules []C.Rule,
	proxies map[string]C.Proxy,
) (*RuleMatchResult, *MethodError) {
	metadata, err := buildRuleMatchMetadata(params)
	if err != nil {
		return nil, &MethodError{
			Code:    "invalid_arguments",
			Message: err.Error(),
		}
	}
	result := newRuleMatchResult()

	if metadata.SpecialProxy != "" {
		result.Mode = "special"
		result.Target = metadata.SpecialProxy
		_, rematch := applyRuleMatchPolicyChain(
			result,
			metadata.SpecialProxy,
			metadata,
			proxies,
		)
		if rematch {
			result.addWarning("rematch-target-not-expanded")
		}
		return result, nil
	}
	if metadata.SpecialRules != "" {
		result.addWarning("special-rules-not-expanded")
		return result, nil
	}

	switch mode {
	case tunnel.Direct:
		result.Mode = "direct"
		result.Target = "DIRECT"
		applyRuleMatchPolicyChain(result, result.Target, metadata, proxies)
		return result, nil
	case tunnel.Global:
		result.Mode = "global"
		result.Target = "GLOBAL"
		_, rematch := applyRuleMatchPolicyChain(
			result,
			result.Target,
			metadata,
			proxies,
		)
		if rematch {
			result.addWarning("rematch-target-not-expanded")
		}
		return result, nil
	}

	helper := C.RuleMatchHelper{
		ResolveIP: func() {
			resolveRuleMatchMetadata(metadata, result)
		},
		FindProcess: func() {
			processRuleMatchMetadata(metadata, result)
		},
		CheckPassRule: func(adapterName string) bool {
			return matchProbePassTarget(adapterName, metadata, proxies)
		},
	}

	for index, wrappedRule := range rules {
		rule, enabled := unwrapRuleForMatchProbe(wrappedRule)
		if !enabled {
			continue
		}
		if warning := missingRuleMatchField(rule.RuleType(), params); warning != "" {
			result.addWarning(warning)
			continue
		}
		if rule.RuleType() == C.AND ||
			rule.RuleType() == C.OR ||
			rule.RuleType() == C.NOT {
			result.addWarning("compound-rule-context-partial")
		}
		matched, target := rule.Match(metadata, helper)
		if !matched {
			continue
		}
		adapter, exists := proxies[target]
		if !exists {
			result.addWarning("matched-target-unavailable")
			continue
		}
		policyChain, skip, rematch, chainWarning := traceRuleMatchPolicy(
			adapter,
			metadata,
		)
		if skip {
			continue
		}
		if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
			continue
		}
		result.Matched = true
		result.RuleIndex = index
		result.RuleType = rule.RuleType().String()
		result.Payload = rule.Payload()
		result.Target = target
		result.PolicyChain = policyChain
		if len(result.PolicyChain) == 0 {
			result.PolicyChain = []string{target}
		}
		result.ProviderNames = append([]string{}, rule.ProviderNames()...)
		if chainWarning != "" {
			result.addWarning(chainWarning)
		}
		if rematch {
			result.addWarning("rematch-target-not-expanded")
		}
		if metadata.DstIP.IsValid() {
			result.ResolvedIP = metadata.DstIP.String()
		}
		return result, nil
	}

	result.Target = "DIRECT"
	applyRuleMatchPolicyChain(result, result.Target, metadata, proxies)
	if metadata.DstIP.IsValid() {
		result.ResolvedIP = metadata.DstIP.String()
	}
	return result, nil
}

func handleRuleMatch(
	params *RuleMatchMetadata,
) (*RuleMatchResult, *MethodError) {
	configMu.Lock()
	mode := tunnel.Mode()
	rules := append([]C.Rule(nil), tunnel.Rules()...)
	proxies := tunnel.AllProxies()
	configMu.Unlock()
	return evaluateRuleMatch(params, mode, rules, proxies)
}

func init() {
	registerMethod(matchRuleMethod, withArguments(func(
		params *RuleMatchMetadata,
		response MethodResponse,
	) {
		safeGo(response, func() {
			result, methodErr := handleRuleMatch(params)
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
