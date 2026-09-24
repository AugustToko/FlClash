package main

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const analyzeDomainMethod CoreMethod = "analyzeDomain"

type DomainAnalysisParams struct {
	Host string `json:"host"`
}

type DomainAnalysisResult struct {
	Input             string `json:"input"`
	NormalizedHost    string `json:"normalizedHost"`
	IsIP              bool   `json:"isIP"`
	PublicSuffix      string `json:"publicSuffix"`
	RegistrableDomain string `json:"registrableDomain"`
	ICANNSuffix       bool   `json:"icannSuffix"`
}

func normalizeDomainAnalysisHost(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("host is empty")
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return "", fmt.Errorf("invalid host %q", raw)
		}
		value = parsed.Hostname()
	} else if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	} else if strings.Count(value, ":") == 1 {
		separator := strings.LastIndexByte(value, ':')
		if separator > 0 {
			if _, err := strconv.ParseUint(value[separator+1:], 10, 16); err == nil {
				value = value[:separator]
			}
		}
	}

	value = strings.TrimSpace(strings.TrimSuffix(value, "."))
	if value == "" {
		return "", fmt.Errorf("host is empty")
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Unmap().String(), nil
	}

	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", raw, err)
	}
	ascii = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ascii), "."))
	if ascii == "" || len(ascii) > 253 {
		return "", fmt.Errorf("invalid domain %q", raw)
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 ||
			strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid domain %q", raw)
		}
	}
	return ascii, nil
}

func analyzeDomain(raw string) (*DomainAnalysisResult, error) {
	normalized, err := normalizeDomainAnalysisHost(raw)
	if err != nil {
		return nil, err
	}
	result := &DomainAnalysisResult{
		Input:          raw,
		NormalizedHost: normalized,
	}
	if _, err := netip.ParseAddr(normalized); err == nil {
		result.IsIP = true
		return result, nil
	}

	result.PublicSuffix, result.ICANNSuffix = publicsuffix.PublicSuffix(normalized)
	registrable, registrableErr := publicsuffix.EffectiveTLDPlusOne(normalized)
	if registrableErr == nil {
		result.RegistrableDomain = strings.ToLower(registrable)
	}
	return result, nil
}

func handleAnalyzeDomain(
	params *DomainAnalysisParams,
) (*DomainAnalysisResult, *MethodError) {
	result, err := analyzeDomain(params.Host)
	if err != nil {
		return nil, &MethodError{
			Code:    "invalid_arguments",
			Message: err.Error(),
		}
	}
	return result, nil
}

func init() {
	registerMethod(analyzeDomainMethod, withArguments(func(
		params *DomainAnalysisParams,
		response MethodResponse,
	) {
		result, methodErr := handleAnalyzeDomain(params)
		if methodErr != nil {
			response.failure(
				methodErr.Code,
				methodErr.Message,
				methodErr.Details,
			)
			return
		}
		response.success(result)
	}))
}
