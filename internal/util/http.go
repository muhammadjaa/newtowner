package util

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// makeHTTPRequest remains largely the same but might need to add X-My-X-Forwarded-For if we decide to do it client-side
func MakeHTTPRequest(ctx context.Context, method, requestURL string, isProxied bool /* headersToInject http.Header */) RequestDetails {
	details := RequestDetails{URL: requestURL, IsProxiedReq: isProxied}
	startTime := time.Now()

	req, err := http.NewRequestWithContext(ctx, method, requestURL, nil)
	if err != nil {
		details.Error = fmt.Sprintf("failed to create request: %v", err)
		details.ResponseTime = time.Since(startTime).Milliseconds()
		return details
	}

	// If this is a proxied request, and we are mimicking the python script's X-Forwarded-For behavior:
	if isProxied {
		if req.Header.Get("X-Forwarded-For") == "" {
			// The python script generates a random IP. For simplicity, we can use a placeholder or a fixed one.
			// Or implement random IP generation later if strictly needed.
			// For now, the python script sets X-My-X-Forwarded-For, which is then mapped by APIGW.
			// So our client should send X-My-X-Forwarded-For.
			req.Header.Set("X-My-X-Forwarded-For", "1.2.3.4") // Placeholder, Python generates random
			// req.Header.Del("X-Forwarded-For") // Python script does this, ensure our client doesn't send it if X-My-X-Forwarded-For is set.
		} else {
			// If X-Forwarded-For is already set, python script moves it to X-My-X-Forwarded-For
			req.Header.Set("X-My-X-Forwarded-For", req.Header.Get("X-Forwarded-For"))
			req.Header.Del("X-Forwarded-For")
		}
	}

	var serverCert *x509.Certificate

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := tls.Dial(network, addr, &tls.Config{
				InsecureSkipVerify: true,
			})
			if err != nil {
				return nil, err
			}
			certs := conn.ConnectionState().PeerCertificates
			if len(certs) > 0 {
				serverCert = certs[0]
			}
			return conn, nil
		},
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}
	resp, err := httpClient.Do(req)
	responseTime := time.Since(startTime).Milliseconds()
	details.ResponseTime = responseTime
	if err != nil {
		details.Error = fmt.Sprintf("failed to execute request: %v", err)
		if strings.HasPrefix(requestURL, "https://") {
			details.SSLCertificateError = AppendError(details.SSLCertificateError, fmt.Sprintf("Request execution error prevented cert retrieval: %v", err))
		}
		return details
	}
	defer resp.Body.Close()

	details.StatusCode = resp.StatusCode
	details.Headers = resp.Header

	if strings.HasPrefix(requestURL, "https://") {
		if serverCert != nil {
			pemBlock := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: serverCert.Raw,
			}
			pemBuffer := new(bytes.Buffer)
			if err := pem.Encode(pemBuffer, pemBlock); err == nil {
				details.SSLCertificatePEM = pemBuffer.String()
			} else {
				details.SSLCertificateError = AppendError(details.SSLCertificateError, "Failed to PEM encode certificate")
			}
		} else if details.Error == "" {
			details.SSLCertificateError = AppendError(details.SSLCertificateError, "Failed to retrieve peer certificate during TLS handshake.")
		}
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		details.Error = AppendError(details.Error, fmt.Sprintf("failed to read response body: %v", err))
	} else {
		details.Body = string(bodyBytes)
		hash := sha256.Sum256(bodyBytes)
		details.BodySHA256 = hex.EncodeToString(hash[:])
	}
	return details
}

// ParseHeaders takes a string containing HTTP headers and parses it into an http.Header map.
// It expects headers in the format "Key: Value\n", one per line.
// It skips the HTTP status line if present.
func ParseHeaders(headersString string) (http.Header, error) {
	h := make(http.Header)
	scanner := bufio.NewScanner(strings.NewReader(headersString))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue // Skip empty lines
		}
		// Skip HTTP status line (e.g., "HTTP/1.1 200 OK")
		if strings.HasPrefix(strings.ToUpper(line), "HTTP/") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			h.Add(key, value)
		} else {
			// Could be a malformed header line, or the status line if not caught above
			// For now, we just skip it. Depending on strictness, you might error here.
		}
	}
	if err := scanner.Err(); err != nil {
		return h, err
	}
	return h, nil
}

// SanitizeURLPrefix removes "http://" or "https://://" from the beginning of a string.
func SanitizeURLPrefix(s string) string {
	if strings.HasPrefix(s, "https://") {
		return strings.TrimPrefix(s, "https://")
	}
	if strings.HasPrefix(s, "http://") {
		return strings.TrimPrefix(s, "http://")
	}
	return s
}
