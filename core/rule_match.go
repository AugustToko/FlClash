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
	matchRuleMethod          CoreMethod = "matchRule"
	defaultRuleMatchScope               = "default"
	maxRuleMatchPolicyDepth             = 64
	maxRuleMatchRematchDepth            = 64
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

type RuleMatchTraceStep struct {
	RuleScope   string   `json:"ruleScope"`
	RuleIndex   int      `json:"ruleIndex"`
	RuleType    string   `json:"ruleType"`
	Payload     string   `json:"payload"`
	Target      string   `json:"target"`
	PolicyChain []string `json:"policyChain"`
	Outcome     string   `json:"outcome"`
	RematchName string   `json:"rematchName"`
	SubRule     string   `json:"subRule"`
}

type RuleMatchResult struct {
	Mode          string               `json:"mode"`
	Matched       bool                 `json:"matched"`
	RuleScope     string               `json:"ruleScope"`
	RuleIndex     int                  `json:"ruleIndex"`
	RuleType      string               `json:"ruleType"`
	Payload       string               `json:"payload"`
	Target        string               `json:"target"`
	PolicyChain   []string             `json:"policyChain"`
	RuleTrace     []RuleMatchTraceStep `json:"ruleTrace"`
	ProviderNames []string             `json:"providerNames"`
	ResolvedIP    string               `json:"resolvedIP"`
	Complete      bool                 `json:"complete"`
	Warnings      []string             `json:"warnings"`
}

func newRuleMatchResult() *RuleMatchResult {
	return &RuleMatchResult{
		Mode:          "rule",
		RuleIndex:     -1,
		PolicyChain:   []string{},
		RuleTrace:     []RuleMatchTraceStep{},
		ProviderNames: []string{},
		Warnings:      []string{},
		Complete:      true,
	}
}

func (result *RuleMatchResult) addWarning(value string) {
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
) (chain []string, skip bool, rematch C.Proxy, warning string) {
	chain = make([]string, 0, 4)
	seen := make(map[string]struct{})
	for depth, current := 0, adapter; current != nil; depth++ {
		if depth >= maxRuleMatchPolicyDepth {
			return chain, false, nil, "policy-chain-truncated"
		}
		identity := ruleMatchProxyIdentity(current)
		if _, exists := seen[identity]; exists {
			return chain, false, nil, "policy-chain-cycle"
		}
		seen[identity] = struct{}{}
		if name := strings.TrimSpace(current.Name()); name != "" &&
			(len(chain) == 0 || chain[len(chain)-1] != name) {
			chain = append(chain, name)
		}
		switch current.Type() {
		case C.Pass:
			return chain, true, nil, ""
		case C.Rematch:
			return chain, false, current, ""
		}
		next := current.Unwrap(metadata, false)
		if next == nil && proxyTypeMayContainPolicy(current.Type()) {
			return chain, false, nil, "policy-chain-unresolved"
		}
		current = next
	}
	return chain, false, nil, ""
}

func applyRuleMatchPolicyChain(
	result *RuleMatchResult,
	target string,
	metadata *C.Metadata,
	proxies map[string]C.Proxy,
) (skip bool, rematch C.Proxy) {
	target = strings.TrimSpace(target)
	if target == "" {
		return false, nil
	}
	adapter, exists := proxies[target]
	if !exists {
		result.PolicyChain = []string{target}
		return false, nil
	}
	chain, skip, rematch, warning := traceRuleMatchPolicy(adapter, metadata)
	if len(chain) == 0 {
		chain = []string{target}
	}
	result.PolicyChain = chain
	result.addWarning(warning)
	return skip, rematch
}

func activeRuleMatchRules(
	metadata *C.Metadata,
	rules []C.Rule,
	subRules map[string][]C.Rule,
	result *RuleMatchResult,
) ([]C.Rule, string) {
	if metadata.SpecialRules != "" {
		if scoped, exists := subRules[metadata.SpecialRules]; exists {
			return scoped, metadata.SpecialRules
		}
		result.addWarning("sub-rule-target-unavailable")
	}
	return rules, defaultRuleMatchScope
}

func isCompoundRuleMatchType(ruleType C.RuleType) bool {
	return ruleType == C.AND || ruleType == C.OR || ruleType == C.NOT
}

func newRuleMatchTraceStep(
	scope string,
	index int,
	rule C.Rule,
	target string,
	policyChain []string,
	outcome string,
	metadata *C.Metadata,
) RuleMatchTraceStep {
	return RuleMatchTraceStep{
		RuleScope:   scope,
		RuleIndex:   index,
		RuleType:    rule.RuleType().String(),
		Payload:     rule.Payload(),
		Target:      target,
		PolicyChain: append([]string(nil), policyChain...),
		Outcome:     outcome,
		RematchName: metadata.RematchName,
		SubRule:     metadata.SpecialRules,
	}
}

func finalizeRuleMatch(
	result *RuleMatchResult,
	scope string,
	index int,
	rule C.Rule,
	target string,
	policyChain []string,
	metadata *C.Metadata,
) {
	result.Matched = true
	result.RuleScope = scope
	result.RuleIndex = index
	result.RuleType = rule.RuleType().String()
	result.Payload = rule.Payload()
	result.Target = target
	result.PolicyChain = append([]string(nil), policyChain...)
	if len(result.PolicyChain) == 0 {
		result.PolicyChain = []string{target}
	}
	result.ProviderNames = append([]string{}, rule.ProviderNames()...)
	if metadata.DstIP.IsValid() {
		result.ResolvedIP = metadata.DstIP.String()
	}
}

func evaluateRuleMatch(
	params *RuleMatchMetadata,
	mode tunnel.TunnelMode,
	rules []C.Rule,
	subRules map[string][]C.Rule,
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
		if rematch != nil {
			result.addWarning("rematch-target-not-expanded")
		}
		if metadata.DstIP.IsValid() {
			result.ResolvedIP = metadata.DstIP.String()
		}
		return result, nil
	}

	switch mode {
	case tunnel.Direct:
		result.Mode = "direct"
		result.Target = "DIRECT"
		_, rematch := applyRuleMatchPolicyChain(
			result,
			result.Target,
			metadata,
			proxies,
		)
		if rematch != nil {
			result.addWarning("rematch-target-not-expanded")
		}
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
		if rematch != nil {
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

	rematchSeen := make(map[string]struct{})
	for {
		activeRules, scope := activeRuleMatchRules(
			metadata,
			rules,
			subRules,
			result,
		)
		rematched := false
		for index, wrappedRule := range activeRules {
			rule, enabled := unwrapRuleForMatchProbe(wrappedRule)
			if !enabled {
				continue
			}
			if warning := missingRuleMatchField(rule.RuleType(), params); warning != "" {
				result.addWarning(warning)
				continue
			}
			matched, target := rule.Match(metadata, helper)
			if !matched {
				continue
			}
			if isCompoundRuleMatchType(rule.RuleType()) {
				result.addWarning("compound-rule-context-partial")
			}
			adapter, exists := proxies[target]
			if !exists {
				result.RuleTrace = append(
					result.RuleTrace,
					newRuleMatchTraceStep(
						scope,
						index,
						rule,
						target,
						[]string{target},
						"target-unavailable",
						metadata,
					),
				)
				result.addWarning("matched-target-unavailable")
				continue
			}
			policyChain, skip, rematchProxy, chainWarning := traceRuleMatchPolicy(
				adapter,
				metadata,
			)
			if len(policyChain) == 0 {
				policyChain = []string{target}
			}
			result.addWarning(chainWarning)
			if skip {
				result.RuleTrace = append(
					result.RuleTrace,
					newRuleMatchTraceStep(
						scope,
						index,
						rule,
						target,
						policyChain,
						"pass",
						metadata,
					),
				)
				continue
			}
			if rematchProxy != nil {
				step := newRuleMatchTraceStep(
					scope,
					index,
					rule,
					target,
					policyChain,
					"rematch",
					metadata,
				)
				rematchName := rematchProxy.Name()
				if _, exists := rematchSeen[rematchName]; exists {
					step.Outcome = "rematch-cycle"
					result.RuleTrace = append(result.RuleTrace, step)
					result.addWarning("rematch-cycle")
					finalizeRuleMatch(
						result,
						scope,
						index,
						rule,
						target,
						policyChain,
						metadata,
					)
					return result, nil
				}
				if len(rematchSeen) >= maxRuleMatchRematchDepth {
					step.Outcome = "rematch-truncated"
					result.RuleTrace = append(result.RuleTrace, step)
					result.addWarning("rematch-chain-truncated")
					finalizeRuleMatch(
						result,
						scope,
						index,
						rule,
						target,
						policyChain,
						metadata,
					)
					return result, nil
				}
				rematchSeen[rematchName] = struct{}{}
				conn, rematchErr := rematchProxy.DialContext(
					context.Background(),
					metadata,
				)
				if conn != nil {
					_ = conn.Close()
				}
				step.RematchName = metadata.RematchName
				step.SubRule = metadata.SpecialRules
				if rematchErr != nil {
					step.Outcome = "rematch-error"
					result.RuleTrace = append(result.RuleTrace, step)
					result.addWarning("rematch-metadata-update-failed")
					finalizeRuleMatch(
						result,
						scope,
						index,
						rule,
						target,
						policyChain,
						metadata,
					)
					return result, nil
				}
				result.RuleTrace = append(result.RuleTrace, step)
				rematched = true
				break
			}
			if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
				result.RuleTrace = append(
					result.RuleTrace,
					newRuleMatchTraceStep(
						scope,
						index,
						rule,
						target,
						policyChain,
						"udp-unsupported",
						metadata,
					),
				)
				continue
			}

			result.RuleTrace = append(
				result.RuleTrace,
				newRuleMatchTraceStep(
					scope,
					index,
					rule,
					target,
					policyChain,
					"final",
					metadata,
				),
			)
			finalizeRuleMatch(
				result,
				scope,
				index,
				rule,
				target,
				policyChain,
				metadata,
			)
			return result, nil
		}
		if rematched {
			continue
		}

		result.RuleScope = scope
		result.Target = "DIRECT"
		applyRuleMatchPolicyChain(result, result.Target, metadata, proxies)
		if metadata.DstIP.IsValid() {
			result.ResolvedIP = metadata.DstIP.String()
		}
		return result, nil
	}
}

func snapshotRuleMatchConfiguration() (
	mode tunnel.TunnelMode,
	rules []C.Rule,
	subRules map[string][]C.Rule,
	proxies map[string]C.Proxy,
) {
	configMu.Lock()
	defer configMu.Unlock()

	mode = tunnel.Mode()
	if currentConfig != nil {
		rules = append([]C.Rule(nil), currentConfig.Rules...)
		subRules = make(map[string][]C.Rule, len(currentConfig.SubRules))
		for name, scopedRules := range currentConfig.SubRules {
			subRules[name] = append([]C.Rule(nil), scopedRules...)
		}
	} else {
		rules = append([]C.Rule(nil), tunnel.Rules()...)
		subRules = map[string][]C.Rule{}
	}
	proxies = tunnel.AllProxies()
	return
}

func handleRuleMatch(
	params *RuleMatchMetadata,
) (*RuleMatchResult, *MethodError) {
	mode, rules, subRules, proxies := snapshotRuleMatchConfiguration()
	return evaluateRuleMatch(params, mode, rules, subRules, proxies)
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
