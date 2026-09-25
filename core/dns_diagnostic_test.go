package main

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	R "github.com/metacubex/mihomo/component/resolver"
	D "github.com/miekg/dns"
)

type dnsDiagnosticResolverStub struct {
	message   *D.Msg
	err       error
	available bool
	question  D.Question
}

func (stub *dnsDiagnosticResolverStub) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return nil, errors.New("not implemented")
}

func (stub *dnsDiagnosticResolverStub) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	return nil, errors.New("not implemented")
}

func (stub *dnsDiagnosticResolverStub) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return nil, errors.New("not implemented")
}

func (stub *dnsDiagnosticResolverStub) ResolveECH(context.Context, string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (stub *dnsDiagnosticResolverStub) ExchangeContext(_ context.Context, message *D.Msg) (*D.Msg, error) {
	if len(message.Question) != 0 {
		stub.question = message.Question[0]
	}
	if stub.message == nil {
		return nil, stub.err
	}
	return stub.message.Copy(), stub.err
}

func (stub *dnsDiagnosticResolverStub) Invalid() bool    { return stub.available }
func (stub *dnsDiagnosticResolverStub) ClearCache()      {}
func (stub *dnsDiagnosticResolverStub) ResetConnection() {}

func withDNSDiagnosticResolvers(
	t *testing.T,
	defaultResolver R.Resolver,
	systemResolver R.Resolver,
	proxyResolver R.Resolver,
	directResolver R.Resolver,
) {
	t.Helper()
	originalDefault := R.DefaultResolver
	originalSystem := R.SystemResolver
	originalProxy := R.ProxyServerHostResolver
	originalDirect := R.DirectHostResolver
	R.DefaultResolver = defaultResolver
	R.SystemResolver = systemResolver
	R.ProxyServerHostResolver = proxyResolver
	R.DirectHostResolver = directResolver
	t.Cleanup(func() {
		R.DefaultResolver = originalDefault
		R.SystemResolver = originalSystem
		R.ProxyServerHostResolver = originalProxy
		R.DirectHostResolver = originalDirect
	})
}

func dnsDiagnosticReply(name string, queryType uint16) *D.Msg {
	query := new(D.Msg)
	query.SetQuestion(D.Fqdn(name), queryType)
	response := new(D.Msg)
	response.SetReply(query)
	response.RecursionAvailable = true
	return response
}

func TestDNSQueryReturnsStructuredRecords(t *testing.T) {
	message := dnsDiagnosticReply("api.example.com", D.TypeA)
	message.Answer = []D.RR{
		&D.CNAME{
			Hdr:    D.RR_Header{Name: "api.example.com.", Rrtype: D.TypeCNAME, Class: D.ClassINET, Ttl: 120},
			Target: "edge.example.net.",
		},
		&D.A{
			Hdr: D.RR_Header{Name: "edge.example.net.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
			A:   []byte{1, 1, 1, 1},
		},
	}
	message.Ns = []D.RR{
		&D.NS{
			Hdr: D.RR_Header{Name: "example.com.", Rrtype: D.TypeNS, Class: D.ClassINET, Ttl: 300},
			Ns:  "ns1.example.com.",
		},
	}
	resolver := &dnsDiagnosticResolverStub{message: message, available: true}
	withDNSDiagnosticResolvers(t, resolver, nil, nil, nil)

	result, methodErr := handleDNSQuery(&DNSQueryParams{
		Name:      "https://Api.Example.com.:443/path",
		QueryType: "a",
		Resolver:  "default",
		TimeoutMS: 1000,
	})

	if methodErr != nil {
		t.Fatalf("handleDNSQuery: %v", methodErr)
	}
	if result.Name != "api.example.com" || result.QuestionName != "api.example.com" {
		t.Fatalf("name = %q / question = %q", result.Name, result.QuestionName)
	}
	if result.QueryType != "A" || result.Resolver != dnsResolverDefault {
		t.Fatalf("type/resolver = %q/%q", result.QueryType, result.Resolver)
	}
	if result.Status != "NOERROR" || result.RCode != D.RcodeSuccess {
		t.Fatalf("status = %q (%d)", result.Status, result.RCode)
	}
	if !result.RecursionAvailable || !result.Complete {
		t.Fatalf("flags = %+v", result)
	}
	if len(result.Answers) != 2 || result.Answers[0].Data != "edge.example.net" || result.Answers[1].Data != "1.1.1.1" {
		t.Fatalf("answers = %#v", result.Answers)
	}
	if len(result.Authority) != 1 || result.Authority[0].Data != "ns1.example.com" {
		t.Fatalf("authority = %#v", result.Authority)
	}
	if resolver.question.Name != "api.example.com." || resolver.question.Qtype != D.TypeA {
		t.Fatalf("question = %#v", resolver.question)
	}
}

func TestDNSQueryFallsBackToSystemResolverExplicitly(t *testing.T) {
	message := dnsDiagnosticReply("example.com", D.TypeAAAA)
	message.Answer = []D.RR{
		&D.AAAA{
			Hdr:  D.RR_Header{Name: "example.com.", Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 42},
			AAAA: netip.MustParseAddr("2001:db8::1").AsSlice(),
		},
	}
	systemResolver := &dnsDiagnosticResolverStub{message: message, available: true}
	withDNSDiagnosticResolvers(t, nil, systemResolver, nil, nil)

	result, methodErr := handleDNSQuery(&DNSQueryParams{
		Name:      "example.com",
		QueryType: "AAAA",
		Resolver:  "default",
	})

	if methodErr != nil {
		t.Fatalf("handleDNSQuery: %v", methodErr)
	}
	if result.RequestedResolver != dnsResolverDefault || result.Resolver != dnsResolverSystem {
		t.Fatalf("resolver = %q -> %q", result.RequestedResolver, result.Resolver)
	}
	if !slices.Contains(result.Warnings, "default-resolver-unavailable") {
		t.Fatalf("warnings = %v", result.Warnings)
	}
	if got := result.Answers[0].Data; got != "2001:db8::1" {
		t.Fatalf("AAAA = %q", got)
	}
}

func TestDNSQueryBuildsPTRQuestionFromIPAddress(t *testing.T) {
	message := dnsDiagnosticReply("4.3.2.1.in-addr.arpa", D.TypePTR)
	message.Answer = []D.RR{
		&D.PTR{
			Hdr: D.RR_Header{Name: "4.3.2.1.in-addr.arpa.", Rrtype: D.TypePTR, Class: D.ClassINET, Ttl: 30},
			Ptr: "host.example.com.",
		},
	}
	resolver := &dnsDiagnosticResolverStub{message: message, available: true}
	withDNSDiagnosticResolvers(t, resolver, nil, nil, nil)

	result, methodErr := handleDNSQuery(&DNSQueryParams{
		Name:      "1.2.3.4",
		QueryType: "PTR",
	})

	if methodErr != nil {
		t.Fatalf("handleDNSQuery: %v", methodErr)
	}
	if result.Name != "1.2.3.4" || result.QuestionName != "4.3.2.1.in-addr.arpa" {
		t.Fatalf("PTR names = %q / %q", result.Name, result.QuestionName)
	}
	if resolver.question.Name != "4.3.2.1.in-addr.arpa." {
		t.Fatalf("question = %q", resolver.question.Name)
	}
	if result.Answers[0].Data != "host.example.com" {
		t.Fatalf("PTR data = %q", result.Answers[0].Data)
	}
}

func TestDNSQueryKeepsNoAnswerAndTruncationExplicit(t *testing.T) {
	message := dnsDiagnosticReply("example.com", D.TypeTXT)
	message.Truncated = true
	resolver := &dnsDiagnosticResolverStub{message: message, available: true}
	withDNSDiagnosticResolvers(t, resolver, nil, nil, nil)

	result, methodErr := handleDNSQuery(&DNSQueryParams{Name: "example.com", QueryType: "TXT"})

	if methodErr != nil {
		t.Fatalf("handleDNSQuery: %v", methodErr)
	}
	if result.Complete || !result.Truncated {
		t.Fatalf("complete/truncated = %v/%v", result.Complete, result.Truncated)
	}
	for _, warning := range []string{"no-answer-records", "truncated-response"} {
		if !slices.Contains(result.Warnings, warning) {
			t.Fatalf("warnings = %v", result.Warnings)
		}
	}
}

func TestDNSQueryRejectsInvalidContracts(t *testing.T) {
	tests := []DNSQueryParams{
		{Name: "example.com", QueryType: "ANY"},
		{Name: "1.1.1.1", QueryType: "A"},
		{Name: "example.com", QueryType: "A", Resolver: "unknown"},
		{Name: "example.com:notaport", QueryType: "A"},
	}
	for _, params := range tests {
		if result, methodErr := handleDNSQuery(&params); methodErr == nil || result != nil || methodErr.Code != "invalid_arguments" {
			t.Fatalf("params %#v => result %#v error %#v", params, result, methodErr)
		}
	}
}

func TestDNSQueryReportsUnavailableAndTimeoutResolvers(t *testing.T) {
	withDNSDiagnosticResolvers(t, nil, nil, nil, nil)
	if result, methodErr := handleDNSQuery(&DNSQueryParams{
		Name: "example.com", QueryType: "A", Resolver: "direct",
	}); methodErr == nil || result != nil || methodErr.Code != "dns_resolver_unavailable" {
		t.Fatalf("unavailable result = %#v, error = %#v", result, methodErr)
	}

	timeoutResolver := &dnsDiagnosticResolverStub{
		err:       context.DeadlineExceeded,
		available: true,
	}
	withDNSDiagnosticResolvers(t, timeoutResolver, nil, nil, nil)
	if result, methodErr := handleDNSQuery(&DNSQueryParams{
		Name: "example.com", QueryType: "A", TimeoutMS: 1,
	}); methodErr == nil || result != nil || methodErr.Code != "dns_query_failed" {
		t.Fatalf("timeout result = %#v, error = %#v", result, methodErr)
	} else if details, ok := methodErr.Details.(map[string]any); !ok || details["failureKind"] != "timeout" {
		t.Fatalf("timeout details = %#v", methodErr.Details)
	}
}

func TestDNSQueryTimeoutIsBounded(t *testing.T) {
	if got := dnsQueryTimeout(1); got != 250*time.Millisecond {
		t.Fatalf("minimum timeout = %s", got)
	}
	if got := dnsQueryTimeout(60000); got != 15*time.Second {
		t.Fatalf("maximum timeout = %s", got)
	}
	if got := dnsQueryTimeout(0); got != R.DefaultDNSTimeout {
		t.Fatalf("default timeout = %s", got)
	}
}

func TestDNSQueryMethodIsRegistered(t *testing.T) {
	if _, exists := methodHandlers[queryDnsMethod]; !exists {
		t.Fatal("queryDns core method is not registered")
	}
}
