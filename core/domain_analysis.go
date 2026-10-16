package core

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

func validateDomainAnalysisPort(port string) error {
	if port == "" {
		return nil
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}

func normalizeDomainAnalysisHost(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("host is empty")
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return "", fmt.Errorf("invalid host %q", raw)
		}
		if err := validateDomainAnalysisPort(parsed.Port()); err != nil {
			return "", fmt.Errorf("invalid host %q: %w", raw, err)
		}
		value = parsed.Hostname()
	} else if host, port, err := net.SplitHostPort(value); err == nil {
		if err := validateDomainAnalysisPort(port); err != nil {
			return "", fmt.Errorf("invalid host %q: %w", raw, err)
		}
		value = host
	} else if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	}

	value = strings.TrimSpace(strings.TrimSuffix(value, "."))
	if value == "" {
		return "", errors.New("host is empty")
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

func analyzeDomain(raw string) (DomainAnalysisResult, error) {
	normalized, err := normalizeDomainAnalysisHost(raw)
	if err != nil {
		return DomainAnalysisResult{}, err
	}
	result := DomainAnalysisResult{
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

func handleAnalyzeDomain(params DomainAnalysisParams) (DomainAnalysisResult, error) {
	result, err := analyzeDomain(params.Host)
	if err != nil {
		return DomainAnalysisResult{}, &MethodError{
			Code:    "invalid_arguments",
			Message: err.Error(),
		}
	}
	return result, nil
}
