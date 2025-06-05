package util

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/agnivade/levenshtein"
	"github.com/charmbracelet/lipgloss"
)

// RequestDetails holds information about an HTTP request and its response.
// It's designed to be compatible with the JSON output of the Python http_check_runner.py script.
type RequestDetails struct {
	URL          string      `json:"url"`
	StatusCode   int         `json:"status_code"`
	Headers      http.Header `json:"headers"` // Reverted to http.Header
	BodySHA256   string      `json:"body_sha256"`
	ResponseTime int64       `json:"response_time_ms"` // Assuming Python sends int (was string)
	Error        string      `json:"error,omitempty"`
	Body         string      `json:"body,omitempty"`
	BodyBase64   string      `json:"body_base64,omitempty"` // For binary/undecodable bodies

	// SSL Certificate Information from Python script
	SSLCertificatePEM   string `json:"ssl_certificate_pem,omitempty"`
	SSLCertificateError string `json:"ssl_certificate_error,omitempty"`

	// Fields below are not directly from the Python script's primary output,
	// but might be populated or used internally in Go.
	IsProxiedReq bool `json:"-"` // True if this request was made via a proxy
}

// HeaderValueDiff stores the values of a header that exists in both responses but differs.
type HeaderValueDiff struct {
	DirectValue  string
	ProxiedValue string
}

// ComparisonResult holds the outcome of comparing two requests.
type ComparisonResult struct {
	StatusCodesMatch         bool
	BodySHA256Match          bool
	BodySignificantlySimilar bool // Based on Levenshtein >= 95% similarity
	BodySimilarityPercentage float64
	Notes                    string

	// Detailed header differences
	DirectOnlyHeaders          http.Header                // Headers present only in the direct response
	ProxiedOnlyHeaders         http.Header                // Headers present only in the proxied response (excluding AWS internal ones)
	DifferentValueHeaders      map[string]HeaderValueDiff // Headers present in both but with different values; key is canonical header name
	ProxiedSpecificCookieNames []string                   // Names of cookies set by proxied response but not by direct

	// Old field for compatibility or if specific string values are used by other logic.
	HeadersComparison map[string]string // Key: header name, Value: "match", "mismatch", "only_direct", "only_proxied"

	// SSL Certificate Comparison Details
	DirectSSLCertError         string `json:"direct_ssl_cert_error,omitempty"`
	ProxiedSSLCertError        string `json:"proxied_ssl_cert_error,omitempty"`
	SSLCertificatesMatch       bool   `json:"ssl_certificates_match"` // Overall match indicator
	SSLCertSubjectMatch        bool   `json:"ssl_cert_subject_match"`
	SSLCertIssuerMatch         bool   `json:"ssl_cert_issuer_match"`
	SSLCertSerialMatch         bool   `json:"ssl_cert_serial_match"`
	SSLCertNotValidBeforeMatch bool   `json:"ssl_cert_not_valid_before_match"`
	SSLCertNotValidAfterMatch  bool   `json:"ssl_cert_not_valid_after_match"`
	SSLCertSigAlgoMatch        bool   `json:"ssl_cert_sig_algo_match"`
	SSLCertCommonNameMatch     bool   `json:"ssl_cert_common_name_match"`
	SSLCertSubjectAltNameMatch bool   `json:"ssl_cert_subject_alt_name_match"`
	SSLCertKeyUsageMatch       bool   `json:"ssl_cert_key_usage_match"`
	SSLCertExtKeyUsageMatch    bool   `json:"ssl_cert_ext_key_usage_match"`
	SSLCertIsCAMatch           bool   `json:"ssl_cert_is_ca_match"`
	SSLCertPublicKeyAlgoMatch  bool   `json:"ssl_cert_public_key_algorithm_match"`
	// Store differing SSL fields for detailed reporting if needed by display logic later
	SSLDiffFields map[string]HeaderValueDiff `json:"ssl_diff_fields,omitempty"`
}

// Constants for header formatting (package-level, unexported as they are used internally by FormatHeaders and DisplayHeaderDiff)
const (
	maxHeaderValueLen = 50
	indent            = "  "
)

// headersToFilter is unexported, used internally by FormatHeaders and DisplayHeaderDiff within this package.
var headersToFilter = map[string]bool{
	"X-Amz-Apigw-Id":                 true,
	"X-Amzn-Remapped-Connection":     true,
	"X-Amzn-Remapped-Content-Length": true,
	"X-Amzn-Remapped-Date":           true,
	"X-Amzn-Requestid":               true,
	"X-Amzn-Trace-Id":                true,
	"Date":                           true, // Added to filter from display if desired
}

// Exported Lipgloss styles for header diffing, so main package can use them if needed (though DisplayHeaderDiff is self-contained)
var (
	StyleHeaderDirectOnly  = lipgloss.NewStyle().Foreground(lipgloss.Color("208")) // Orange for direct-only headers
	StyleHeaderProxiedOnly = lipgloss.NewStyle().Foreground(lipgloss.Color("220")) // Yellow for proxied-only headers
	StyleHeaderKeyCommon   = lipgloss.NewStyle().Foreground(lipgloss.Color("248")) // Grey for common keys, if we decide to show them
)

// Define our own simple diff types
type diffType int

const (
	diffEqual diffType = iota
	diffInsert
	diffDelete
)

type diffOperation struct {
	Type diffType
	Text string // For delete and equal, this is from body1. For insert, this is from body2.
}

// generateLCSDiffOperations performs a line-based LCS diff and returns a sequence of operations.
func generateLCSDiffOperations(s1, s2 string) []diffOperation {
	// normalize lines to ensure consistent splitting
	lineEndingReplacer := strings.NewReplacer("\r\n", "\n", "\r", "\n")
	s1Processed := lineEndingReplacer.Replace(s1)
	s2Processed := lineEndingReplacer.Replace(s2)

	lines1 := strings.Split(s1Processed, "\n")
	lines2 := strings.Split(s2Processed, "\n")
	n, m := len(lines1), len(lines2)

	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}

	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if lines1[i-1] == lines2[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				if dp[i-1][j] > dp[i][j-1] {
					dp[i][j] = dp[i-1][j]
				} else {
					dp[i][j] = dp[i][j-1]
				}
			}
		}
	}

	var ops []diffOperation
	i, j := n, m
	for i > 0 || j > 0 {
		if i > 0 && j > 0 && lines1[i-1] == lines2[j-1] {
			ops = append(ops, diffOperation{Type: diffEqual, Text: lines1[i-1]})
			i--
			j--
		} else if j > 0 && (i == 0 || dp[i][j-1] >= dp[i-1][j]) {
			ops = append(ops, diffOperation{Type: diffInsert, Text: lines2[j-1]})
			j--
		} else if i > 0 && (j == 0 || dp[i-1][j] > dp[i][j-1]) {
			ops = append(ops, diffOperation{Type: diffDelete, Text: lines1[i-1]})
			i--
		} else {
			break
		}
	}

	for k, l := 0, len(ops)-1; k < l; k, l = k+1, l-1 {
		ops[k], ops[l] = ops[l], ops[k]
	}
	return ops
}

// GenerateDiffOutput takes two strings and generates a side-by-side, colored
// diff string using lipgloss for rendering, based on LCS.
func GenerateDiffOutput(body1, body2 string) (string, error) {
	diffOps := generateLCSDiffOperations(body1, body2)

	var leftColumnBuilder, rightColumnBuilder strings.Builder
	var leftMarkerBuilder, rightMarkerBuilder strings.Builder

	const colWidth = 68
	styleNormal := lipgloss.NewStyle().Width(colWidth).MaxWidth(colWidth)
	styleAdded := lipgloss.NewStyle().Width(colWidth).MaxWidth(colWidth).Foreground(lipgloss.Color("10"))
	styleRemoved := lipgloss.NewStyle().Width(colWidth).MaxWidth(colWidth).Foreground(lipgloss.Color("9"))

	emptyStyledColSegment := styleNormal.Render(" ")

	for _, op := range diffOps {
		var rawLeftText, rawRightText string
		currentLeftStyle, currentRightStyle := styleNormal, styleNormal
		currentLeftMarkerText, currentRightMarkerText := "  ", "  "

		switch op.Type {
		case diffEqual:
			rawLeftText = op.Text
			rawRightText = op.Text
		case diffInsert:
			rawLeftText = " "
			rawRightText = op.Text
			currentRightStyle = styleAdded
			currentRightMarkerText = "+ "
		case diffDelete:
			rawLeftText = op.Text
			rawRightText = " "
			currentLeftStyle = styleRemoved
			currentLeftMarkerText = "- "
		}

		renderedLeftBlock := currentLeftStyle.Render(rawLeftText)
		renderedRightBlock := currentRightStyle.Render(rawRightText)

		leftBlockLines := strings.Split(renderedLeftBlock, "\n")
		rightBlockLines := strings.Split(renderedRightBlock, "\n")
		numDisplayLinesForOp := max(len(leftBlockLines), len(rightBlockLines))

		for i := 0; i < numDisplayLinesForOp; i++ {
			if i < len(leftBlockLines) {
				leftColumnBuilder.WriteString(leftBlockLines[i])
			} else {
				leftColumnBuilder.WriteString(emptyStyledColSegment)
			}
			leftColumnBuilder.WriteString("\n")

			if i < len(rightBlockLines) {
				rightColumnBuilder.WriteString(rightBlockLines[i])
			} else {
				rightColumnBuilder.WriteString(emptyStyledColSegment)
			}
			rightColumnBuilder.WriteString("\n")

			if i == 0 {
				leftMarkerBuilder.WriteString(currentLeftMarkerText)
				rightMarkerBuilder.WriteString(currentRightMarkerText)
			} else {
				leftMarkerBuilder.WriteString("  ")
				rightMarkerBuilder.WriteString("  ")
			}
			leftMarkerBuilder.WriteString("\n")
			rightMarkerBuilder.WriteString("\n")
		}
	}

	finalLeftMarkers := strings.Split(strings.TrimSuffix(leftMarkerBuilder.String(), "\n"), "\n")
	finalLeftColumns := strings.Split(strings.TrimSuffix(leftColumnBuilder.String(), "\n"), "\n")
	finalRightMarkers := strings.Split(strings.TrimSuffix(rightMarkerBuilder.String(), "\n"), "\n")
	finalRightColumns := strings.Split(strings.TrimSuffix(rightColumnBuilder.String(), "\n"), "\n")

	var finalOutputBuilder strings.Builder
	totalLines := len(finalLeftColumns)

	markerStyleDefault := lipgloss.NewStyle().Foreground(lipgloss.Color("242"))
	markerStyleAdded := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	markerStyleRemoved := lipgloss.NewStyle().Foreground(lipgloss.Color("9"))

	for i := 0; i < totalLines; i++ {
		leftMarkerToRender := "  "
		if i < len(finalLeftMarkers) {
			leftMarkerToRender = finalLeftMarkers[i]
		}
		leftColOriginal := emptyStyledColSegment
		if i < len(finalLeftColumns) {
			leftColOriginal = finalLeftColumns[i]
		}
		rightMarkerToRender := "  "
		if i < len(finalRightMarkers) {
			rightMarkerToRender = finalRightMarkers[i]
		}
		rightColOriginal := emptyStyledColSegment
		if i < len(finalRightColumns) {
			rightColOriginal = finalRightColumns[i]
		}

		leftColVisualWidth := lipgloss.Width(leftColOriginal)
		leftPadding := ""
		if leftColVisualWidth < colWidth {
			leftPadding = strings.Repeat(" ", colWidth-leftColVisualWidth)
		}
		finalLeftCol := leftColOriginal + leftPadding

		rightColVisualWidth := lipgloss.Width(rightColOriginal)
		rightPadding := ""
		if rightColVisualWidth < colWidth {
			rightPadding = strings.Repeat(" ", colWidth-rightColVisualWidth)
		}
		finalRightCol := rightColOriginal + rightPadding

		currentLeftMarkerStyle := markerStyleDefault
		if strings.HasPrefix(leftMarkerToRender, "-") {
			currentLeftMarkerStyle = markerStyleRemoved
		}
		currentRightMarkerStyle := markerStyleDefault
		if strings.HasPrefix(rightMarkerToRender, "+") {
			currentRightMarkerStyle = markerStyleAdded
		}

		joinedLine := lipgloss.JoinHorizontal(lipgloss.Top,
			currentLeftMarkerStyle.Render(leftMarkerToRender),
			finalLeftCol,
			" │ ",
			currentRightMarkerStyle.Render(rightMarkerToRender),
			finalRightCol,
		)
		finalOutputBuilder.WriteString(joinedLine)
		if i < totalLines-1 {
			finalOutputBuilder.WriteString("\n")
		}
	}

	return finalOutputBuilder.String(), nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func parseCookieNames(setCookieHeaders []string) map[string]bool {
	names := make(map[string]bool)
	for _, headerValue := range setCookieHeaders {
		parts := strings.SplitN(headerValue, ";", 2)
		if len(parts) > 0 {
			cookiePair := parts[0]
			nameValue := strings.SplitN(cookiePair, "=", 2)
			if len(nameValue) > 0 {
				name := strings.TrimSpace(nameValue[0])
				if name != "" {
					names[name] = true
				}
			}
		}
	}
	return names
}

func DisplayHeaderDiff(comp ComparisonResult, directHeaders http.Header, proxiedHeaders http.Header) {
	var displayedSomething bool
	valueStyle := lipgloss.NewStyle()

	sanitizeAndTruncate := func(vals []string) string {
		if len(vals) == 0 {
			return "(not present)"
		}
		sanitized := make([]string, len(vals))
		for i, v := range vals {
			tv := strings.ReplaceAll(v, "\n", " ")
			tv = strings.ReplaceAll(tv, "\r", " ")
			if len(tv) > maxHeaderValueLen {
				tv = tv[:maxHeaderValueLen] + "..."
			}
			sanitized[i] = tv
		}
		return strings.Join(sanitized, ", ")
	}

	if len(comp.DirectOnlyHeaders) > 0 {
		fmt.Printf("%s%s:\n", indent, StyleHeaderDirectOnly.Render("Headers unique to Direct Request"))
		sortedDirectOnlyKeys := make([]string, 0, len(comp.DirectOnlyHeaders))
		for k := range comp.DirectOnlyHeaders {
			sortedDirectOnlyKeys = append(sortedDirectOnlyKeys, k)
		}
		sort.Strings(sortedDirectOnlyKeys)
		for _, k := range sortedDirectOnlyKeys {
			if _, isGloballyFiltered := headersToFilter[http.CanonicalHeaderKey(k)]; isGloballyFiltered {
				continue
			}
			valDisplay := sanitizeAndTruncate(comp.DirectOnlyHeaders[k])
			fmt.Printf("%s  %s: %s\n", indent, StyleHeaderDirectOnly.Render(k), valueStyle.Render(valDisplay))
			displayedSomething = true
		}
	}

	if len(comp.ProxiedOnlyHeaders) > 0 {
		fmt.Printf("%s%s:\n", indent, StyleHeaderProxiedOnly.Render("Headers unique to API Gateway Request"))
		sortedProxiedOnlyKeys := make([]string, 0, len(comp.ProxiedOnlyHeaders))
		for k := range comp.ProxiedOnlyHeaders {
			sortedProxiedOnlyKeys = append(sortedProxiedOnlyKeys, k)
		}
		sort.Strings(sortedProxiedOnlyKeys)
		for _, k := range sortedProxiedOnlyKeys {
			if _, isGloballyFiltered := headersToFilter[http.CanonicalHeaderKey(k)]; isGloballyFiltered {
				continue
			}
			valDisplay := sanitizeAndTruncate(comp.ProxiedOnlyHeaders[k])
			fmt.Printf("%s  %s: %s\n", indent, StyleHeaderProxiedOnly.Render(k), valueStyle.Render(valDisplay))
			displayedSomething = true
		}
	}

	if len(comp.ProxiedSpecificCookieNames) > 0 {
		fmt.Printf("%s%s:\n", indent, StyleHeaderProxiedOnly.Render("New Cookies from API Gateway"))
		for _, cookieName := range comp.ProxiedSpecificCookieNames {
			fmt.Printf("%s  %s\n", indent, StyleHeaderProxiedOnly.Render(cookieName))
			displayedSomething = true
		}
	}

	if !displayedSomething {
		fmt.Printf("%s(No unique headers or new cookies to display after filtering, or all header keys match.)\n", indent)
	}
}

func GetFormattedHeaderDiffElements(comp ComparisonResult) (
	directKVPairs []string,
	proxiedKVPairs []string,
	newCookieNames []string,
	hasDirect bool,
	hasProxied bool,
	hasCookies bool,
) {
	directKVPairs = []string{}
	proxiedKVPairs = []string{}
	newCookieNames = []string{}
	valueStyle := lipgloss.NewStyle()

	sanitizeAndTruncate := func(vals []string) string {
		if len(vals) == 0 {
			return "(not present)"
		}
		sanitized := make([]string, len(vals))
		for i, v := range vals {
			tv := strings.ReplaceAll(v, "\n", " ")
			tv = strings.ReplaceAll(tv, "\r", " ")
			if len(tv) > maxHeaderValueLen {
				tv = tv[:maxHeaderValueLen] + "..."
			}
			sanitized[i] = tv
		}
		return strings.Join(sanitized, ", ")
	}

	if len(comp.DirectOnlyHeaders) > 0 {
		sortedDirectOnlyKeys := make([]string, 0, len(comp.DirectOnlyHeaders))
		for k := range comp.DirectOnlyHeaders {
			sortedDirectOnlyKeys = append(sortedDirectOnlyKeys, k)
		}
		sort.Strings(sortedDirectOnlyKeys)
		for _, k := range sortedDirectOnlyKeys {
			if _, isGloballyFiltered := headersToFilter[http.CanonicalHeaderKey(k)]; isGloballyFiltered {
				continue
			}
			valDisplay := sanitizeAndTruncate(comp.DirectOnlyHeaders[k])
			directKVPairs = append(directKVPairs, StyleHeaderDirectOnly.Render(k)+": "+valueStyle.Render(valDisplay))
			hasDirect = true
		}
	}

	if len(comp.ProxiedOnlyHeaders) > 0 {
		sortedProxiedOnlyKeys := make([]string, 0, len(comp.ProxiedOnlyHeaders))
		for k := range comp.ProxiedOnlyHeaders {
			sortedProxiedOnlyKeys = append(sortedProxiedOnlyKeys, k)
		}
		sort.Strings(sortedProxiedOnlyKeys)
		for _, k := range sortedProxiedOnlyKeys {
			if _, isGloballyFiltered := headersToFilter[http.CanonicalHeaderKey(k)]; isGloballyFiltered {
				continue
			}
			valDisplay := sanitizeAndTruncate(comp.ProxiedOnlyHeaders[k])
			proxiedKVPairs = append(proxiedKVPairs, StyleHeaderProxiedOnly.Render(k)+": "+valueStyle.Render(valDisplay))
			hasProxied = true
		}
	}

	if len(comp.ProxiedSpecificCookieNames) > 0 {
		for _, cookieName := range comp.ProxiedSpecificCookieNames {
			newCookieNames = append(newCookieNames, StyleHeaderProxiedOnly.Render(cookieName))
			hasCookies = true
		}
	}

	return
}

func FormatHeaders(headers http.Header, isAPIGateway bool) string {
	if headers == nil || len(headers) == 0 {
		return "(no headers)"
	}
	var parts []string
	sortedKeys := make([]string, 0, len(headers))
	for k := range headers {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	for _, k := range sortedKeys {
		if isAPIGateway {
			if _, shouldFilter := headersToFilter[http.CanonicalHeaderKey(k)]; shouldFilter {
				continue
			}
		}
		vRaw := headers[k]
		sanitizedValues := make([]string, len(vRaw))
		for i, val := range vRaw {
			tempVal := strings.ReplaceAll(val, "\n", " ")
			tempVal = strings.ReplaceAll(tempVal, "\r", " ")
			if len(tempVal) > maxHeaderValueLen {
				tempVal = tempVal[:maxHeaderValueLen] + "..."
			}
			sanitizedValues[i] = tempVal
		}
		valStr := strings.Join(sanitizedValues, ", ")
		parts = append(parts, k+": "+valStr)
	}
	if len(parts) == 0 {
		return "(no displayable headers after filtering)"
	}
	return "\n" + indent + strings.Join(parts, "\n"+indent)
}

// isIgnorableDirectError checks if the error message from a direct request
// indicates a type of error (like TLS handshake failures) that should be
// considered a potential bypass if the proxied request succeeds.
func isIgnorableDirectError(errMsg string) bool {
	if errMsg == "" {
		return false
	}
	// Add more specific error substrings as needed
	// Common TLS/handshake errors often include these phrases.
	// Consider making these configurable or more extensive if needed.
	patterns := []string{
		"tls: handshake failure",
		"remote error: tls:",                            // More generic TLS error
		"certificate verify failed",                     // Added
		"x509: certificate signed by unknown authority", // Added
		"connection refused",
		"connection reset by peer",
		"timeout",      // Could be a network block
		"no such host", // DNS resolution failure locally
	}
	for _, pattern := range patterns {
		if strings.Contains(errMsg, pattern) {
			return true
		}
	}
	return false
}

// ParseCertificateFromPEM parses a PEM encoded certificate and returns an x509.Certificate
func ParseCertificateFromPEM(pemData string) (*x509.Certificate, error) {
	if pemData == "" {
		return nil, fmt.Errorf("PEM data is empty")
	}
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

// Helper function to compare two SSL certificates and populate comparison result
func compareSSLCertificates(direct, proxied RequestDetails, comp *ComparisonResult) {
	// Store SSL errors from direct and proxied requests
	comp.DirectSSLCertError = direct.SSLCertificateError
	comp.ProxiedSSLCertError = proxied.SSLCertificateError

	// Check if both URLs are HTTPS
	isDirectHTTPS := strings.HasPrefix(direct.URL, "https://")
	isProxiedHTTPS := strings.HasPrefix(proxied.URL, "https://")

	// Handle HTTP-only cases
	if !isDirectHTTPS && !isProxiedHTTPS {
		resetSSLMatchesToTrue(comp)
		comp.Notes = AppendError(comp.Notes, "Both URLs are HTTP, SSL certificate comparison not applicable. ")
		return
	}

	// Handle mixed HTTP/HTTPS cases
	if isDirectHTTPS != isProxiedHTTPS {
		resetSSLMatchesToFalse(comp)
		comp.SSLCertificatesMatch = false
		comp.Notes = AppendError(comp.Notes, "One URL is HTTP and the other is HTTPS; SSL certificates cannot match. ")
		return
	}

	// Both are HTTPS, parse certificates
	directCert, directParseErr := ParseCertificateFromPEM(direct.SSLCertificatePEM)
	if directParseErr != nil && direct.SSLCertificatePEM != "" {
		comp.DirectSSLCertError = AppendError(comp.DirectSSLCertError, fmt.Sprintf("PEM parse error: %v", directParseErr))
	} else if direct.SSLCertificatePEM == "" && direct.SSLCertificateError == "" {
		comp.DirectSSLCertError = AppendError(comp.DirectSSLCertError, "Direct PEM is empty but URL is HTTPS and no prior SSL error reported.")
	}

	proxiedCert, proxiedParseErr := ParseCertificateFromPEM(proxied.SSLCertificatePEM)
	if proxiedParseErr != nil && proxied.SSLCertificatePEM != "" {
		comp.ProxiedSSLCertError = AppendError(comp.ProxiedSSLCertError, fmt.Sprintf("PEM parse error: %v", proxiedParseErr))
	} else if proxied.SSLCertificatePEM == "" && proxied.SSLCertificateError == "" {
		comp.ProxiedSSLCertError = AppendError(comp.ProxiedSSLCertError, "Proxied PEM is empty but URL is HTTPS and no prior SSL error reported by script.")
	}

	// Compare certificates if both parsed successfully
	if directCert != nil && proxiedCert != nil {
		performDetailedCertComparison(directCert, proxiedCert, comp)
	} else {
		handleCertParseFailure(directCert, proxiedCert, directParseErr, proxiedParseErr, comp)
	}
}

// Helper to reset all SSL match fields to true (for HTTP cases)
func resetSSLMatchesToTrue(comp *ComparisonResult) {
	comp.SSLCertificatesMatch = true
	comp.SSLCertSubjectMatch = true
	comp.SSLCertIssuerMatch = true
	comp.SSLCertSerialMatch = true
	comp.SSLCertNotValidBeforeMatch = true
	comp.SSLCertNotValidAfterMatch = true
	comp.SSLCertSigAlgoMatch = true
	comp.SSLCertCommonNameMatch = true
	comp.SSLCertSubjectAltNameMatch = true
	comp.SSLCertKeyUsageMatch = true
	comp.SSLCertExtKeyUsageMatch = true
	comp.SSLCertIsCAMatch = true
	comp.SSLCertPublicKeyAlgoMatch = true
	comp.SSLDiffFields = make(map[string]HeaderValueDiff)
}

// Helper to reset all SSL match fields to false (for mixed HTTP/HTTPS cases)
func resetSSLMatchesToFalse(comp *ComparisonResult) {
	comp.SSLCertSubjectMatch = false
	comp.SSLCertIssuerMatch = false
	comp.SSLCertSerialMatch = false
	comp.SSLCertNotValidBeforeMatch = false
	comp.SSLCertNotValidAfterMatch = false
	comp.SSLCertSigAlgoMatch = false
	comp.SSLCertCommonNameMatch = false
	comp.SSLCertSubjectAltNameMatch = false
	comp.SSLCertKeyUsageMatch = false
	comp.SSLCertExtKeyUsageMatch = false
	comp.SSLCertIsCAMatch = false
	comp.SSLCertPublicKeyAlgoMatch = false
}

// Helper to perform detailed certificate field comparison
func performDetailedCertComparison(directCert, proxiedCert *x509.Certificate, comp *ComparisonResult) {
	// Compare basic certificate fields
	comp.SSLCertSubjectMatch = compareAndRecord(directCert.Subject.String(), proxiedCert.Subject.String(), "Subject", comp)
	comp.SSLCertCommonNameMatch = compareAndRecord(directCert.Subject.CommonName, proxiedCert.Subject.CommonName, "CommonName", comp)
	comp.SSLCertIssuerMatch = compareAndRecord(directCert.Issuer.String(), proxiedCert.Issuer.String(), "Issuer", comp)
	comp.SSLCertSerialMatch = compareAndRecord(directCert.SerialNumber.String(), proxiedCert.SerialNumber.String(), "Serial Number", comp)
	comp.SSLCertSigAlgoMatch = compareAndRecord(directCert.SignatureAlgorithm.String(), proxiedCert.SignatureAlgorithm.String(), "Signature Algorithm", comp)
	comp.SSLCertPublicKeyAlgoMatch = compareAndRecord(directCert.PublicKeyAlgorithm.String(), proxiedCert.PublicKeyAlgorithm.String(), "Public Key Algorithm", comp)

	// Compare dates
	comp.SSLCertNotValidBeforeMatch = compareDatesAndRecord(directCert.NotBefore, proxiedCert.NotBefore, "Not Valid Before", comp)
	comp.SSLCertNotValidAfterMatch = compareDatesAndRecord(directCert.NotAfter, proxiedCert.NotAfter, "Not Valid After", comp)

	// Compare boolean fields
	comp.SSLCertIsCAMatch = compareBoolAndRecord(directCert.IsCA, proxiedCert.IsCA, "Is CA", comp)

	// Compare Key Usage
	comp.SSLCertKeyUsageMatch = compareKeyUsageAndRecord(directCert.KeyUsage, proxiedCert.KeyUsage, comp)

	// Compare Extended Key Usage
	comp.SSLCertExtKeyUsageMatch = compareExtKeyUsageAndRecord(directCert.ExtKeyUsage, proxiedCert.ExtKeyUsage, comp)

	// Compare Subject Alternative Names
	comp.SSLCertSubjectAltNameMatch = compareSANsAndRecord(directCert, proxiedCert, comp)

	// Calculate overall SSL certificates match
	comp.SSLCertificatesMatch = comp.SSLCertSubjectMatch && comp.SSLCertIssuerMatch && comp.SSLCertSerialMatch &&
		comp.SSLCertNotValidBeforeMatch && comp.SSLCertNotValidAfterMatch && comp.SSLCertSigAlgoMatch &&
		comp.SSLCertCommonNameMatch && comp.SSLCertSubjectAltNameMatch && comp.SSLCertKeyUsageMatch &&
		comp.SSLCertExtKeyUsageMatch && comp.SSLCertIsCAMatch && comp.SSLCertPublicKeyAlgoMatch
}

// Helper function to compare string values and record differences
func compareAndRecord(directVal, proxiedVal, fieldName string, comp *ComparisonResult) bool {
	match := directVal == proxiedVal
	if !match {
		comp.SSLDiffFields[fieldName] = HeaderValueDiff{DirectValue: directVal, ProxiedValue: proxiedVal}
	}
	return match
}

// Helper function to compare dates and record differences
func compareDatesAndRecord(directDate, proxiedDate time.Time, fieldName string, comp *ComparisonResult) bool {
	match := directDate.Equal(proxiedDate)
	if !match {
		comp.SSLDiffFields[fieldName] = HeaderValueDiff{
			DirectValue:  directDate.UTC().Format(time.RFC3339),
			ProxiedValue: proxiedDate.UTC().Format(time.RFC3339),
		}
	}
	return match
}

// Helper function to compare boolean values and record differences
func compareBoolAndRecord(directVal, proxiedVal bool, fieldName string, comp *ComparisonResult) bool {
	match := directVal == proxiedVal
	if !match {
		comp.SSLDiffFields[fieldName] = HeaderValueDiff{
			DirectValue:  strconv.FormatBool(directVal),
			ProxiedValue: strconv.FormatBool(proxiedVal),
		}
	}
	return match
}

// Helper function to compare KeyUsage and record differences
func compareKeyUsageAndRecord(directUsage, proxiedUsage x509.KeyUsage, comp *ComparisonResult) bool {
	match := directUsage == proxiedUsage
	if !match {
		comp.SSLDiffFields["Key Usage"] = HeaderValueDiff{
			DirectValue:  formatKeyUsage(directUsage),
			ProxiedValue: formatKeyUsage(proxiedUsage),
		}
	}
	return match
}

// Helper function to compare ExtKeyUsage and record differences
func compareExtKeyUsageAndRecord(directUsages, proxiedUsages []x509.ExtKeyUsage, comp *ComparisonResult) bool {
	match := compareExtKeyUsageSlices(directUsages, proxiedUsages)
	if !match {
		comp.SSLDiffFields["Extended Key Usage"] = HeaderValueDiff{
			DirectValue:  formatExtKeyUsages(directUsages),
			ProxiedValue: formatExtKeyUsages(proxiedUsages),
		}
	}
	return match
}

// Helper function to compare Subject Alternative Names and record differences
func compareSANsAndRecord(directCert, proxiedCert *x509.Certificate, comp *ComparisonResult) bool {
	dnsMatch := compareStringSlices(directCert.DNSNames, proxiedCert.DNSNames)
	ipMatch := compareNetIPSlices(directCert.IPAddresses, proxiedCert.IPAddresses)

	if !dnsMatch {
		comp.SSLDiffFields["Subject Alt Names (DNS)"] = HeaderValueDiff{
			DirectValue:  strings.Join(directCert.DNSNames, ", "),
			ProxiedValue: strings.Join(proxiedCert.DNSNames, ", "),
		}
	}
	if !ipMatch {
		comp.SSLDiffFields["Subject Alt Names (IP)"] = HeaderValueDiff{
			DirectValue:  formatIPAddresses(directCert.IPAddresses),
			ProxiedValue: formatIPAddresses(proxiedCert.IPAddresses),
		}
	}

	return dnsMatch && ipMatch
}

// Helper to handle cases where certificate parsing failed
func handleCertParseFailure(directCert, proxiedCert *x509.Certificate, directParseErr, proxiedParseErr error, comp *ComparisonResult) {
	comp.SSLCertificatesMatch = false

	if directCert == nil && directParseErr != nil {
		comp.Notes = AppendError(comp.Notes, fmt.Sprintf("Direct SSL Cert Parse Error: %s. ", directParseErr))
	} else if directCert == nil {
		comp.Notes = AppendError(comp.Notes, "Direct SSL Cert Error or missing PEM. ")
	}

	if proxiedCert == nil && proxiedParseErr != nil {
		comp.Notes = AppendError(comp.Notes, fmt.Sprintf("Proxied SSL Cert Parse Error: %s. ", proxiedParseErr))
	} else if proxiedCert == nil {
		comp.Notes = AppendError(comp.Notes, "Proxied SSL Cert Error or missing PEM. ")
	}

	if directCert != nil && proxiedCert == nil {
		comp.Notes = AppendError(comp.Notes, "Direct has a valid SSL cert, proxied does not. ")
	}
	if proxiedCert != nil && directCert == nil {
		comp.Notes = AppendError(comp.Notes, "Proxied has a valid SSL cert, direct does not. ")
	}
}

func CompareHTTPResponses(direct RequestDetails, proxied RequestDetails) (ComparisonResult, bool, string) {
	comp := ComparisonResult{
		HeadersComparison:          make(map[string]string),
		DirectOnlyHeaders:          make(http.Header),
		ProxiedOnlyHeaders:         make(http.Header),
		DifferentValueHeaders:      make(map[string]HeaderValueDiff),
		ProxiedSpecificCookieNames: make([]string, 0),
		SSLDiffFields:              make(map[string]HeaderValueDiff),
		SSLCertificatesMatch:       true,
		SSLCertSubjectMatch:        true,
		SSLCertIssuerMatch:         true,
		SSLCertSerialMatch:         true,
		SSLCertNotValidBeforeMatch: true,
		SSLCertNotValidAfterMatch:  true,
		SSLCertSigAlgoMatch:        true,
		SSLCertCommonNameMatch:     true,
		SSLCertSubjectAltNameMatch: true,
		SSLCertKeyUsageMatch:       true,
		SSLCertExtKeyUsageMatch:    true,
		SSLCertIsCAMatch:           true,
		SSLCertPublicKeyAlgoMatch:  true,
	}
	var potentialBypass bool
	var bypassReason strings.Builder

	if proxied.Error != "" {
		comp.Notes = fmt.Sprintf("Comparison not possible: Provider request failed: %s. ", proxied.Error)
		if direct.Error != "" {
			comp.Notes += fmt.Sprintf("Direct request also failed: %s. ", direct.Error)
		}
		comp.SSLCertificatesMatch = false
		return comp, false, comp.Notes
	}

	if direct.Error != "" {
		if isIgnorableDirectError(direct.Error) {
			potentialBypass = true
			bypassReason.WriteString(fmt.Sprintf(
				"Potential bypass: Direct request failed (%s), but provider request succeeded (Status: %d).",
				TrimmedString(direct.Error, 100),
				proxied.StatusCode,
			))
			comp.Notes = fmt.Sprintf("Direct request error: %s. Provider request successful. ", direct.Error)
			comp.StatusCodesMatch = false
			comp.BodySHA256Match = false
			comp.BodySignificantlySimilar = false
			comp.BodySimilarityPercentage = 0.0
			comp.SSLCertificatesMatch = false
			return comp, potentialBypass, bypassReason.String()
		}
		comp.Notes = fmt.Sprintf("Comparison not fully possible: Direct request failed: %s. Provider request was successful. ", direct.Error)
		comp.SSLCertificatesMatch = false
		return comp, false, comp.Notes
	}

	// SSL Certificate Comparison
	compareSSLCertificates(direct, proxied, &comp)

	// Status Code & Body Comparison (existing logic)
	comp.StatusCodesMatch = direct.StatusCode == proxied.StatusCode
	comp.BodySHA256Match = direct.BodySHA256 == proxied.BodySHA256

	if len(direct.Body) == 0 && len(proxied.Body) == 0 {
		comp.BodySignificantlySimilar = true
		comp.BodySimilarityPercentage = 100.0
	} else if (len(direct.Body) == 0 && len(proxied.Body) > 0) || (len(direct.Body) > 0 && len(proxied.Body) == 0) {
		comp.BodySignificantlySimilar = false
		comp.BodySimilarityPercentage = 0.0
		comp.Notes = AppendError(comp.Notes, "One body is empty while the other is not. ")
	} else {
		distance := levenshtein.ComputeDistance(direct.Body, proxied.Body)
		maxLength := math.Max(float64(len(direct.Body)), float64(len(proxied.Body)))
		if maxLength == 0 {
			comp.BodySimilarityPercentage = 100.0
		} else {
			comp.BodySimilarityPercentage = (1.0 - (float64(distance) / maxLength)) * 100.0
		}
		comp.BodySignificantlySimilar = comp.BodySimilarityPercentage >= 95.0
	}

	allHeaderKeys := make(map[string]bool)
	awsHeadersToIgnoreForComparisonLogic := map[string]bool{
		"X-Amz-Apigw-Id":                 true,
		"X-Amzn-Trace-Id":                true,
		"X-Amzn-Remapped-Date":           true,
		"X-Amzn-Remapped-Content-Length": true,
		"X-Amzn-Remapped-Connection":     true,
		"X-Amzn-Requestid":               true,
		"Date":                           true,
	}

	if direct.Headers != nil {
		for k := range direct.Headers {
			allHeaderKeys[http.CanonicalHeaderKey(k)] = true
		}
	}
	if proxied.Headers != nil {
		for k := range proxied.Headers {
			allHeaderKeys[http.CanonicalHeaderKey(k)] = true
		}
	}

	setCookieKey := http.CanonicalHeaderKey("Set-Cookie")
	directCookieHeaderValues := direct.Headers[setCookieKey]
	proxiedCookieHeaderValues := proxied.Headers[setCookieKey]

	directCookieNames := parseCookieNames(directCookieHeaderValues)
	proxiedCookieNames := parseCookieNames(proxiedCookieHeaderValues)

	for pCookieName := range proxiedCookieNames {
		if !directCookieNames[pCookieName] {
			comp.ProxiedSpecificCookieNames = append(comp.ProxiedSpecificCookieNames, pCookieName)
		}
	}
	sort.Strings(comp.ProxiedSpecificCookieNames)

	for k := range allHeaderKeys {
		directValues, directExists := direct.Headers[k]
		proxiedValues, proxiedExists := proxied.Headers[k]
		isIgnoredProxiedHeader := false
		if _, ignore := awsHeadersToIgnoreForComparisonLogic[k]; ignore {
			isIgnoredProxiedHeader = true
		}

		sort.Strings(directValues)
		sort.Strings(proxiedValues)
		directValStr := strings.Join(directValues, ", ")
		proxiedValStr := strings.Join(proxiedValues, ", ")

		if directExists && proxiedExists {
			if k == setCookieKey {
			}
			if isIgnoredProxiedHeader {
				comp.HeadersComparison[k] = "match_key_ignored_value_diff"
			} else if strings.EqualFold(directValStr, proxiedValStr) {
				comp.HeadersComparison[k] = "match"
			} else {
				comp.HeadersComparison[k] = fmt.Sprintf("mismatch_value (Direct: '%s' vs Proxied: '%s')", directValStr, proxiedValStr)
				comp.DifferentValueHeaders[k] = HeaderValueDiff{DirectValue: directValStr, ProxiedValue: proxiedValStr}
			}
		} else if directExists {
			comp.HeadersComparison[k] = "only_direct"
			comp.DirectOnlyHeaders[k] = directValues
		} else if proxiedExists {
			if !isIgnoredProxiedHeader {
				comp.HeadersComparison[k] = "only_proxied"
				comp.ProxiedOnlyHeaders[k] = proxiedValues
			} else {
				comp.HeadersComparison[k] = "only_proxied_ignored"
			}
		}
	}

	// --- Notes and Bypass Logic (existing logic, may need updates based on SSL mismatch) ---
	if !comp.StatusCodesMatch {
		comp.Notes = AppendError(comp.Notes, fmt.Sprintf("Status codes differ (Direct: %d, Proxied: %d). ", direct.StatusCode, proxied.StatusCode))
	}
	if !comp.BodySignificantlySimilar {
		comp.Notes = AppendError(comp.Notes, fmt.Sprintf("Body similarity %.2f%%. ", comp.BodySimilarityPercentage))
	}

	// Refined notes based on all comparisons including SSL
	// Check if all primary aspects (status, body, headers, cookies, SSL) match
	uniqueDirectCount := 0
	for key := range comp.DirectOnlyHeaders {
		if _, filterDisplay := headersToFilter[http.CanonicalHeaderKey(key)]; !filterDisplay {
			uniqueDirectCount++
		}
	}
	uniqueProxiedCount := 0
	for key := range comp.ProxiedOnlyHeaders {
		if _, filterDisplay := headersToFilter[http.CanonicalHeaderKey(key)]; !filterDisplay {
			uniqueProxiedCount++
		}
	}
	newCookieCount := len(comp.ProxiedSpecificCookieNames)

	if comp.StatusCodesMatch && comp.BodySignificantlySimilar && uniqueDirectCount == 0 && uniqueProxiedCount == 0 && newCookieCount == 0 && comp.SSLCertificatesMatch {
		comp.Notes = fmt.Sprintf("All aspects match: Status codes, body similarity high (%.2f%%), no unique headers/cookies (after filtering), and SSL certificates match.", comp.BodySimilarityPercentage)
	} else if comp.StatusCodesMatch && comp.BodySignificantlySimilar {
		noteParts := []string{fmt.Sprintf("Status codes match and body similarity is high (%.2f%%)", comp.BodySimilarityPercentage)}
		if uniqueDirectCount > 0 {
			noteParts = append(noteParts, fmt.Sprintf("%d unique direct headers", uniqueDirectCount))
		}
		if uniqueProxiedCount > 0 {
			noteParts = append(noteParts, fmt.Sprintf("%d unique proxied headers", uniqueProxiedCount))
		}
		if newCookieCount > 0 {
			noteParts = append(noteParts, fmt.Sprintf("%d new cookies from proxy", newCookieCount))
		}
		if !comp.SSLCertificatesMatch {
			noteParts = append(noteParts, "SSL certificates differ")
			if len(comp.SSLDiffFields) > 0 {
				noteParts = append(noteParts, fmt.Sprintf("(%d differing SSL fields)", len(comp.SSLDiffFields)))
			}
		}
		comp.Notes = strings.Join(noteParts, ", ") + "."
	} // Add more specific note combinations if necessary

	// --- Bypass Logic incorporating SSL ---
	// A significant SSL difference is when both were expected to be HTTPS and parseable, but their contents differed.
	// We determine this by checking if SSL comparison was applicable and resulted in a mismatch
	isDirectHTTPS := strings.HasPrefix(direct.URL, "https://")
	isProxiedHTTPS := strings.HasPrefix(proxied.URL, "https://")
	significantSslDifference := false
	if isDirectHTTPS && isProxiedHTTPS && !comp.SSLCertificatesMatch {
		// Both are HTTPS and certs don't match - check if it's due to actual cert differences vs errors
		// If we have SSL diff fields, it means we successfully compared cert fields and found differences
		if len(comp.SSLDiffFields) > 0 {
			significantSslDifference = true
		}
	}

	if !comp.StatusCodesMatch || !comp.BodySignificantlySimilar || significantSslDifference {
		potentialBypass = true
		if !comp.StatusCodesMatch {
			bypassReason.WriteString(fmt.Sprintf("Status code mismatch (Direct: %d, Proxied: %d). ", direct.StatusCode, proxied.StatusCode))
		}
		if !comp.BodySignificantlySimilar {
			bypassReason.WriteString(fmt.Sprintf("Body similarity %.2f%% is below 95%% threshold. ", comp.BodySimilarityPercentage))
		}
		if significantSslDifference {
			bypassReason.WriteString("SSL certificates differ significantly. ")
			// Optionally list differing fields:
			// for k, v := range comp.SSLDiffFields {
			// 	bypassReason.WriteString(fmt.Sprintf(" SSL %s: D='%s', P='%s'. ", k, TrimmedString(v.DirectValue, 20), TrimmedString(v.ProxiedValue, 20)))
			// }
		}
	} else { // Status, Body, and critical SSL aspects match or SSL comparison was not definitive (e.g. errors)
		if uniqueDirectCount > 0 || uniqueProxiedCount > 0 || newCookieCount > 0 {
			bypassReason.WriteString("No status/body/SSL bypass. Header/Cookie differences noted: ")
			if uniqueDirectCount > 0 {
				bypassReason.WriteString(fmt.Sprintf("%d headers only in direct. ", uniqueDirectCount))
			}
			if uniqueProxiedCount > 0 {
				bypassReason.WriteString(fmt.Sprintf("%d headers only in proxied. ", uniqueProxiedCount))
			}
			if newCookieCount > 0 {
				bypassReason.WriteString(fmt.Sprintf("%d new cookies from proxied. ", newCookieCount))
			}
		} else if !comp.SSLCertificatesMatch { // Catch cases where SSL errors occurred, or one was HTTP etc.
			// but status/body matched.
			bypassReason.WriteString(fmt.Sprintf("No status/body/header/cookie bypass. SSL certificate differences or errors noted: DirectErr='%s', ProxiedErr='%s'.", TrimmedString(comp.DirectSSLCertError, 50), TrimmedString(comp.ProxiedSSLCertError, 50)))
		} else {
			bypassReason.WriteString("No significant differences detected in status, body, header keys, new cookies, or SSL certificates (after filtering and where applicable).")
		}
	}

	return comp, potentialBypass, bypassReason.String()
}

// TrimmedString shortens a string to a max length, adding "..." if truncated.
func TrimmedString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 { // Not enough space for "..."
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func FormatFullResponse(details RequestDetails) string {
	if details.Error != "" {
		return fmt.Sprintf("Error during request: %s", details.Error)
	}

	var sb strings.Builder

	statusText := http.StatusText(details.StatusCode)
	if statusText == "" {
		statusText = "Status"
	}
	sb.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\n", details.StatusCode, statusText))

	if details.Headers != nil {
		sortedHeaderKeys := make([]string, 0, len(details.Headers))
		for k := range details.Headers {
			sortedHeaderKeys = append(sortedHeaderKeys, k)
		}
		sort.Strings(sortedHeaderKeys)

		for _, k := range sortedHeaderKeys {
			if _, shouldFilter := headersToFilter[http.CanonicalHeaderKey(k)]; shouldFilter {
				continue
			}

			for _, v := range details.Headers[k] {
				sb.WriteString(fmt.Sprintf("%s: %s\n", http.CanonicalHeaderKey(k), v))
			}
		}
	}

	sb.WriteString("\n")

	sb.WriteString(details.Body)

	return sb.String()
}

// IndentString prepends each line of a given string with a specified prefix.
// If the input string is empty, it returns an empty string.
// If the input string does not end with a newline, one is added before returning
// to ensure consistent formatting when multiple indented blocks are concatenated.
func IndentString(s, prefix string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	var indentedLines []string
	for _, line := range lines {
		indentedLines = append(indentedLines, prefix+line)
	}
	result := strings.Join(indentedLines, "\n")
	// Ensure it ends with a newline for consistent block formatting if called multiple times
	if !strings.HasSuffix(result, "\n") {
		result += "\n"
	}
	return result
}

// ProviderResult is an interface that all provider URLCheckResult types should implement.
type ProviderResult interface {
	GetURL() string
	GetTargetHostname() string
	GetTargetResolvedIP() string
	GetTargetGeoCountry() string
	GetTargetGeoRegion() string
	GetProcessingError() string
	GetDirectRequestDetails() RequestDetails
	GetProviderRequestDetails() RequestDetails
	GetProviderDisplayName() string
	GetProviderSubDetails() string
	GetComparisonResult() ComparisonResult
	IsPotentialBypass() bool
	GetBypassReason() string
	ShouldSkipBodyDiff() bool
}

// AppendError appends a new error string to an existing one.
func AppendError(existingError, newError string) string {
	if existingError == "" {
		return newError
	}
	if newError == "" {
		return existingError
	}
	return fmt.Sprintf("%s; %s", existingError, newError)
}

type ProxiedResult struct {
	URL            string              `json:"url"`
	StatusCode     int                 `json:"status_code"`
	Headers        map[string][]string `json:"headers"`
	BodySHA256     string              `json:"body_sha256"`
	ResponseTimeMs int64               `json:"response_time_ms"`
	Error          string              `json:"error,omitempty"`
	Body           string              `json:"body,omitempty"`
	BodyBase64     string              `json:"body_base64,omitempty"`

	SSLCertificatePEM   string `json:"ssl_certificate_pem,omitempty"`
	SSLCertificateError string `json:"ssl_certificate_error,omitempty"`
}

// Helper function to compare string slices (order independent for SANs, etc.)
func compareStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aMap := make(map[string]int)
	for _, str := range a {
		aMap[str]++
	}
	for _, str := range b {
		if count, ok := aMap[str]; !ok || count == 0 {
			return false
		}
		aMap[str]--
	}
	return true
}

// Helper function to compare ExtKeyUsage slices (order independent)
func compareExtKeyUsageSlices(a, b []x509.ExtKeyUsage) bool {
	if len(a) != len(b) {
		return false
	}
	aMap := make(map[x509.ExtKeyUsage]int)
	for _, eku := range a {
		aMap[eku]++
	}
	for _, eku := range b {
		if count, ok := aMap[eku]; !ok || count == 0 {
			return false
		}
		aMap[eku]--
	}
	return true
}

// Helper function to format KeyUsage
func formatKeyUsage(ku x509.KeyUsage) string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}
	if len(usages) == 0 {
		return "None"
	}
	return strings.Join(usages, ", ")
}

// Helper function to format ExtKeyUsages
func formatExtKeyUsages(ekus []x509.ExtKeyUsage) string {
	if len(ekus) == 0 {
		return "None"
	}
	var usageNames []string
	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageAny:
			usageNames = append(usageNames, "Any")
		case x509.ExtKeyUsageServerAuth:
			usageNames = append(usageNames, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			usageNames = append(usageNames, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usageNames = append(usageNames, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usageNames = append(usageNames, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usageNames = append(usageNames, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			usageNames = append(usageNames, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			usageNames = append(usageNames, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			usageNames = append(usageNames, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usageNames = append(usageNames, "OCSPSigning")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			usageNames = append(usageNames, "MicrosoftServerGatedCrypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			usageNames = append(usageNames, "NetscapeServerGatedCrypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			usageNames = append(usageNames, "MicrosoftCommercialCodeSigning")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			usageNames = append(usageNames, "MicrosoftKernelCodeSigning")
		default:
			usageNames = append(usageNames, fmt.Sprintf("Unknown (%d)", eku))
		}
	}
	return strings.Join(usageNames, ", ")
}

// Helper function to compare IP addresses
func compareNetIPSlices(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	aMap := make(map[string]int)
	for _, ip := range a {
		aMap[ip.String()]++
	}
	for _, ip := range b {
		if count, ok := aMap[ip.String()]; !ok || count == 0 {
			return false
		}
		aMap[ip.String()]--
	}
	return true
}

// Helper function to format IP addresses
func formatIPAddresses(ips []net.IP) string {
	if len(ips) == 0 {
		return "None"
	}
	ipStrings := make([]string, len(ips))
	for i, ip := range ips {
		ipStrings[i] = ip.String()
	}
	return strings.Join(ipStrings, ", ")
}
