package main

import "testing"

func TestAnalyzeDomainFindsRegistrableDomain(t *testing.T) {
	result, err := analyzeDomain("Api.Service.Example.CO.UK.:443")
	if err != nil {
		t.Fatalf("analyzeDomain: %v", err)
	}
	if result.NormalizedHost != "api.service.example.co.uk" {
		t.Fatalf("normalized host = %q", result.NormalizedHost)
	}
	if result.PublicSuffix != "co.uk" || !result.ICANNSuffix {
		t.Fatalf(
			"public suffix = %q, ICANN = %v",
			result.PublicSuffix,
			result.ICANNSuffix,
		)
	}
	if result.RegistrableDomain != "example.co.uk" {
		t.Fatalf("registrable domain = %q", result.RegistrableDomain)
	}
}

func TestAnalyzeDomainHonorsPrivateSuffixes(t *testing.T) {
	result, err := analyzeDomain("bar.foo.github.io")
	if err != nil {
		t.Fatalf("analyzeDomain: %v", err)
	}
	if result.PublicSuffix != "github.io" || result.ICANNSuffix {
		t.Fatalf(
			"private suffix = %q, ICANN = %v",
			result.PublicSuffix,
			result.ICANNSuffix,
		)
	}
	if result.RegistrableDomain != "foo.github.io" {
		t.Fatalf("registrable domain = %q", result.RegistrableDomain)
	}
}

func TestAnalyzeDomainNormalizesUnicodeAndURLs(t *testing.T) {
	result, err := analyzeDomain("https://www.食狮.com.cn/path")
	if err != nil {
		t.Fatalf("analyzeDomain: %v", err)
	}
	if result.NormalizedHost != "www.xn--85x722f.com.cn" {
		t.Fatalf("normalized host = %q", result.NormalizedHost)
	}
	if result.RegistrableDomain != "xn--85x722f.com.cn" {
		t.Fatalf("registrable domain = %q", result.RegistrableDomain)
	}
}

func TestAnalyzeDomainKeepsIPAddressesOutOfDomainScopes(t *testing.T) {
	result, err := analyzeDomain("[2001:db8::1]:443")
	if err != nil {
		t.Fatalf("analyzeDomain: %v", err)
	}
	if !result.IsIP || result.NormalizedHost != "2001:db8::1" {
		t.Fatalf("IP result = %#v", result)
	}
	if result.PublicSuffix != "" || result.RegistrableDomain != "" {
		t.Fatalf("IP address received domain scopes: %#v", result)
	}
}

func TestAnalyzeDomainLeavesSingleLabelHostsNarrow(t *testing.T) {
	result, err := analyzeDomain("localhost")
	if err != nil {
		t.Fatalf("analyzeDomain: %v", err)
	}
	if result.RegistrableDomain != "" {
		t.Fatalf("single-label registrable domain = %q", result.RegistrableDomain)
	}
}

func TestAnalyzeDomainRejectsInvalidInput(t *testing.T) {
	for _, value := range []string{"", "bad domain.example", "-bad.example"} {
		if _, err := analyzeDomain(value); err == nil {
			t.Errorf("analyzeDomain(%q) accepted invalid input", value)
		}
	}
}

func TestAnalyzeDomainMethodIsRegistered(t *testing.T) {
	if _, exists := methodHandlers[analyzeDomainMethod]; !exists {
		t.Fatal("analyzeDomain core method is not registered")
	}
}
