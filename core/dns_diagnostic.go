package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	R "github.com/metacubex/mihomo/component/resolver"
	D "github.com/miekg/dns"
)

const (
	dnsResolverDefault = "default"
	dnsResolverSystem  = "system"
	dnsResolverProxy   = "proxy"
	dnsResolverDirect  = "direct"
)

var dnsDiagnosticTypes = map[string]uint16{
	"A":     D.TypeA,
	"AAAA":  D.TypeAAAA,
	"CNAME": D.TypeCNAME,
	"MX":    D.TypeMX,
	"TXT":   D.TypeTXT,
	"NS":    D.TypeNS,
	"SOA":   D.TypeSOA,
	"SRV":   D.TypeSRV,
	"PTR":   D.TypePTR,
	"HTTPS": D.TypeHTTPS,
	"SVCB":  D.TypeSVCB,
}

type DNSQueryParams struct {
	Name      string `json:"name"`
	QueryType string `json:"queryType"`
	Resolver  string `json:"resolver"`
	TimeoutMS int    `json:"timeoutMs"`
}

type DNSDiagnosticRecord struct {
	Section string `json:"section"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Class   string `json:"class"`
	TTL     uint32 `json:"ttl"`
	Data    string `json:"data"`
}

type DNSQueryResult struct {
	Input              string                `json:"input"`
	Name               string                `json:"name"`
	QuestionName       string                `json:"questionName"`
	QueryType          string                `json:"queryType"`
	RequestedResolver  string                `json:"requestedResolver"`
	Resolver           string                `json:"resolver"`
	DurationMS         int64                 `json:"durationMs"`
	RCode              int                   `json:"rcode"`
	Status             string                `json:"status"`
	Authoritative      bool                  `json:"authoritative"`
	Truncated          bool                  `json:"truncated"`
	RecursionAvailable bool                  `json:"recursionAvailable"`
	AuthenticatedData  bool                  `json:"authenticatedData"`
	CheckingDisabled   bool                  `json:"checkingDisabled"`
	Complete           bool                  `json:"complete"`
	Answers            []DNSDiagnosticRecord `json:"answers"`
	Authority          []DNSDiagnosticRecord `json:"authority"`
	Additional         []DNSDiagnosticRecord `json:"additional"`
	Warnings           []string              `json:"warnings"`
}

func normalizeDNSResolverMode(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" || value == "core" || value == "mihomo" {
		return dnsResolverDefault, nil
	}
	switch value {
	case dnsResolverDefault, dnsResolverSystem, dnsResolverProxy, dnsResolverDirect:
		return value, nil
	default:
		return "", fmt.Errorf("unsupported DNS resolver %q", raw)
	}
}

func normalizeDNSQueryType(raw string) (string, uint16, error) {
	value := strings.ToUpper(strings.TrimSpace(raw))
	if value == "" {
		value = "A"
	}
	queryType, exists := dnsDiagnosticTypes[value]
	if !exists {
		keys := make([]string, 0, len(dnsDiagnosticTypes))
		for key := range dnsDiagnosticTypes {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return "", 0, fmt.Errorf(
			"unsupported DNS query type %q; expected one of %s",
			raw,
			strings.Join(keys, ", "),
		)
	}
	return value, queryType, nil
}

func normalizeDNSQueryName(raw, queryType string) (name, question string, err error) {
	normalized, err := normalizeDomainAnalysisHost(raw)
	if err != nil {
		return "", "", err
	}
	address, addressErr := netip.ParseAddr(normalized)
	if queryType == "PTR" {
		if addressErr == nil {
			reverse, reverseErr := D.ReverseAddr(address.Unmap().String())
			if reverseErr != nil {
				return "", "", fmt.Errorf("cannot reverse %q: %w", raw, reverseErr)
			}
			return address.Unmap().String(), reverse, nil
		}
		if !strings.HasSuffix(strings.ToLower(normalized), ".arpa") {
			return "", "", fmt.Errorf("PTR query requires an IP address or reverse DNS name")
		}
		return normalized, D.Fqdn(normalized), nil
	}
	if addressErr == nil {
		return "", "", fmt.Errorf("%s query requires a domain name, not an IP address", queryType)
	}
	return normalized, D.Fqdn(normalized), nil
}

func dnsResolverAvailable(value R.Resolver) (available bool) {
	if value == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			available = false
		}
	}()
	return value.Invalid()
}

func selectDNSDiagnosticResolver(
	requested string,
) (R.Resolver, string, []string, *MethodError) {
	mode, err := normalizeDNSResolverMode(requested)
	if err != nil {
		return nil, "", nil, &MethodError{
			Code:    "invalid_arguments",
			Message: err.Error(),
		}
	}
	selectExplicit := func(value R.Resolver, actual string) (R.Resolver, string, []string, *MethodError) {
		if dnsResolverAvailable(value) {
			return value, actual, nil, nil
		}
		return nil, actual, nil, &MethodError{
			Code:    "dns_resolver_unavailable",
			Message: fmt.Sprintf("DNS resolver %s is unavailable", actual),
			Details: map[string]any{"resolver": actual},
		}
	}
	switch mode {
	case dnsResolverSystem:
		return selectExplicit(R.SystemResolver, dnsResolverSystem)
	case dnsResolverProxy:
		return selectExplicit(R.ProxyServerHostResolver, dnsResolverProxy)
	case dnsResolverDirect:
		return selectExplicit(R.DirectHostResolver, dnsResolverDirect)
	default:
		if dnsResolverAvailable(R.DefaultResolver) {
			return R.DefaultResolver, dnsResolverDefault, nil, nil
		}
		if dnsResolverAvailable(R.SystemResolver) {
			return R.SystemResolver, dnsResolverSystem,
				[]string{"default-resolver-unavailable"}, nil
		}
		return nil, dnsResolverDefault, nil, &MethodError{
			Code:    "dns_resolver_unavailable",
			Message: "both the default and system DNS resolvers are unavailable",
			Details: map[string]any{"resolver": dnsResolverDefault},
		}
	}
}

func dnsRecordData(record D.RR) string {
	switch value := record.(type) {
	case *D.A:
		return value.A.String()
	case *D.AAAA:
		return value.AAAA.String()
	case *D.CNAME:
		return strings.TrimSuffix(value.Target, ".")
	case *D.MX:
		return fmt.Sprintf("%d %s", value.Preference, strings.TrimSuffix(value.Mx, "."))
	case *D.TXT:
		return strings.Join(value.Txt, " ")
	case *D.NS:
		return strings.TrimSuffix(value.Ns, ".")
	case *D.SOA:
		return fmt.Sprintf(
			"%s %s %d %d %d %d %d",
			strings.TrimSuffix(value.Ns, "."),
			strings.TrimSuffix(value.Mbox, "."),
			value.Serial,
			value.Refresh,
			value.Retry,
			value.Expire,
			value.Minttl,
		)
	case *D.SRV:
		return fmt.Sprintf(
			"%d %d %d %s",
			value.Priority,
			value.Weight,
			value.Port,
			strings.TrimSuffix(value.Target, "."),
		)
	case *D.PTR:
		return strings.TrimSuffix(value.Ptr, ".")
	case *D.CAA:
		return fmt.Sprintf("%d %s %s", value.Flag, value.Tag, value.Value)
	}
	fields := strings.Fields(record.String())
	if len(fields) >= 5 {
		return strings.Join(fields[4:], " ")
	}
	return record.String()
}

func dnsRecords(section string, values []D.RR) []DNSDiagnosticRecord {
	if len(values) == 0 {
		return []DNSDiagnosticRecord{}
	}
	result := make([]DNSDiagnosticRecord, 0, len(values))
	for _, record := range values {
		if record == nil || record.Header() == nil {
			continue
		}
		header := record.Header()
		recordType := D.TypeToString[header.Rrtype]
		if recordType == "" {
			recordType = strconv.Itoa(int(header.Rrtype))
		}
		class := D.ClassToString[header.Class]
		if class == "" {
			class = strconv.Itoa(int(header.Class))
		}
		result = append(result, DNSDiagnosticRecord{
			Section: section,
			Name:    strings.TrimSuffix(header.Name, "."),
			Type:    recordType,
			Class:   class,
			TTL:     header.Ttl,
			Data:    dnsRecordData(record),
		})
	}
	return result
}

func dnsQueryTimeout(value int) time.Duration {
	if value == 0 {
		return R.DefaultDNSTimeout
	}
	if value < 250 {
		value = 250
	}
	if value > 15000 {
		value = 15000
	}
	return time.Duration(value) * time.Millisecond
}

func handleDNSQuery(params *DNSQueryParams) (*DNSQueryResult, *MethodError) {
	queryType, dnsType, err := normalizeDNSQueryType(params.QueryType)
	if err != nil {
		return nil, &MethodError{Code: "invalid_arguments", Message: err.Error()}
	}
	name, questionName, err := normalizeDNSQueryName(params.Name, queryType)
	if err != nil {
		return nil, &MethodError{Code: "invalid_arguments", Message: err.Error()}
	}
	requestedResolver, err := normalizeDNSResolverMode(params.Resolver)
	if err != nil {
		return nil, &MethodError{Code: "invalid_arguments", Message: err.Error()}
	}
	selected, actualResolver, warnings, resolverErr := selectDNSDiagnosticResolver(requestedResolver)
	if resolverErr != nil {
		return nil, resolverErr
	}

	query := new(D.Msg)
	query.SetQuestion(questionName, dnsType)
	query.RecursionDesired = true
	startedAt := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), dnsQueryTimeout(params.TimeoutMS))
	defer cancel()
	message, queryErr := selected.ExchangeContext(ctx, query)
	duration := time.Since(startedAt).Milliseconds()
	if queryErr != nil {
		failureKind := "dns_error"
		if errors.Is(queryErr, context.DeadlineExceeded) {
			failureKind = "timeout"
		} else if errors.Is(queryErr, context.Canceled) {
			failureKind = "cancelled"
		}
		return nil, &MethodError{
			Code:    "dns_query_failed",
			Message: queryErr.Error(),
			Details: map[string]any{
				"name":              name,
				"queryType":         queryType,
				"requestedResolver": requestedResolver,
				"resolver":          actualResolver,
				"durationMs":        duration,
				"failureKind":       failureKind,
			},
		}
	}
	if message == nil {
		return nil, &MethodError{
			Code:    "dns_query_failed",
			Message: "DNS resolver returned an empty response",
			Details: map[string]any{
				"name":              name,
				"queryType":         queryType,
				"requestedResolver": requestedResolver,
				"resolver":          actualResolver,
				"durationMs":        duration,
				"failureKind":       "empty_response",
			},
		}
	}

	status := D.RcodeToString[message.Rcode]
	if status == "" {
		status = strconv.Itoa(message.Rcode)
	}
	answers := dnsRecords("answer", message.Answer)
	authority := dnsRecords("authority", message.Ns)
	additional := dnsRecords("additional", message.Extra)
	if len(answers) == 0 {
		warnings = append(warnings, "no-answer-records")
	}
	if message.Truncated {
		warnings = append(warnings, "truncated-response")
	}

	return &DNSQueryResult{
		Input:              params.Name,
		Name:               name,
		QuestionName:       strings.TrimSuffix(questionName, "."),
		QueryType:          queryType,
		RequestedResolver:  requestedResolver,
		Resolver:           actualResolver,
		DurationMS:         duration,
		RCode:              message.Rcode,
		Status:             status,
		Authoritative:      message.Authoritative,
		Truncated:          message.Truncated,
		RecursionAvailable: message.RecursionAvailable,
		AuthenticatedData:  message.AuthenticatedData,
		CheckingDisabled:   message.CheckingDisabled,
		Complete:           !message.Truncated,
		Answers:            answers,
		Authority:          authority,
		Additional:         additional,
		Warnings:           warnings,
	}, nil
}

func init() {
	registerMethod(queryDnsMethod, withArguments(func(
		params *DNSQueryParams,
		response MethodResponse,
	) {
		safeGo(response, func() {
			result, methodErr := handleDNSQuery(params)
			if methodErr != nil {
				response.failure(methodErr.Code, methodErr.Message, methodErr.Details)
				return
			}
			response.success(result)
		})
	}))
}
