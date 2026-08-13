package mcpgrafana

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLSConfig_CreateTLSConfig(t *testing.T) {
	t.Run("nil config returns nil", func(t *testing.T) {
		var config *TLSConfig
		tlsCfg, err := config.CreateTLSConfig()
		assert.NoError(t, err)
		assert.Nil(t, tlsCfg)
	})

	t.Run("skip verify only", func(t *testing.T) {
		config := &TLSConfig{SkipVerify: true}
		tlsCfg, err := config.CreateTLSConfig()
		assert.NoError(t, err)
		require.NotNil(t, tlsCfg)
		assert.True(t, tlsCfg.InsecureSkipVerify)
		assert.Empty(t, tlsCfg.Certificates)
		assert.Nil(t, tlsCfg.RootCAs)
	})

	t.Run("invalid cert file", func(t *testing.T) {
		config := &TLSConfig{
			CertFile: "nonexistent.pem",
			KeyFile:  "nonexistent.key",
		}
		_, err := config.CreateTLSConfig()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load client certificate")
	})

	t.Run("invalid CA file", func(t *testing.T) {
		config := &TLSConfig{
			CAFile: "nonexistent-ca.pem",
		}
		_, err := config.CreateTLSConfig()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read CA certificate")
	})

	t.Run("invalid inline CA", func(t *testing.T) {
		config := &TLSConfig{
			CAPem: "not a pem",
		}
		_, err := config.CreateTLSConfig()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse inline CA certificate")
	})
}

// newTestCAPEM generates a self-signed CA certificate, PEM-encoded. Optional
// extra DNS/IP SANs make it usable as a server certificate as well.
func newTestCAPEM(t *testing.T, commonName string, ips ...net.IP) string {
	t.Helper()
	pemStr, _ := newTestCA(t, commonName, ips...)
	return pemStr
}

// newTestCA generates a self-signed CA certificate and returns it both as PEM
// and as a tls.Certificate that a test server can serve.
func newTestCA(t *testing.T, commonName string, ips ...net.IP) (string, tls.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(pemBytes), tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLSConfig_CAPemAppendsToSystemRoots(t *testing.T) {
	caPEM := newTestCAPEM(t, "tenant-ca")

	tlsCfg, err := (&TLSConfig{CAPem: caPEM}).CreateTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg.RootCAs)

	// The pool must be "system roots PLUS the tenant CA". Comparing against a
	// pool holding only the tenant CA is what catches the x509.NewCertPool()
	// regression, where a tenant's private CA replaced the public roots and
	// broke every other tenant sharing this process.
	systemPool, err := x509.SystemCertPool()
	require.NoError(t, err)
	expected := systemPool.Clone()
	require.True(t, expected.AppendCertsFromPEM([]byte(caPEM)))
	assert.True(t, tlsCfg.RootCAs.Equal(expected), "RootCAs must be the system roots plus the tenant CA")

	tenantOnly := x509.NewCertPool()
	require.True(t, tenantOnly.AppendCertsFromPEM([]byte(caPEM)))
	assert.False(t, tlsCfg.RootCAs.Equal(tenantOnly), "the tenant CA must not replace the system roots")
}

func TestTLSConfig_CAFileAndCAPemBothApplied(t *testing.T) {
	filePEM := newTestCAPEM(t, "ca-from-file")
	inlinePEM := newTestCAPEM(t, "ca-from-header")

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, []byte(filePEM), 0o600))

	tlsCfg, err := (&TLSConfig{CAFile: caFile, CAPem: inlinePEM}).CreateTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg.RootCAs)

	systemPool, err := x509.SystemCertPool()
	require.NoError(t, err)
	expected := systemPool.Clone()
	require.True(t, expected.AppendCertsFromPEM([]byte(filePEM)))
	require.True(t, expected.AppendCertsFromPEM([]byte(inlinePEM)))
	assert.True(t, tlsCfg.RootCAs.Equal(expected), "both the CA file and the inline CA must be in the pool")
}

func TestCAPemVerifiesServerCertificate(t *testing.T) {
	// A TLS server presenting a certificate issued by "tenant-ca". This is the
	// production failure: a Grafana with a privately-issued certificate.
	serverPEM, serverCert := newTestCA(t, "tenant-ca", net.ParseIP("127.0.0.1"))
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	ts.StartTLS()
	defer ts.Close()

	get := func(caPEM string) error {
		transport, err := (&TLSConfig{CAPem: caPEM}).HTTPTransport(http.DefaultTransport.(*http.Transport))
		require.NoError(t, err)
		resp, err := (&http.Client{Transport: transport}).Get(ts.URL)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		return nil
	}

	t.Run("the issuing CA verifies the server", func(t *testing.T) {
		require.NoError(t, get(serverPEM))
	})

	t.Run("a CA that did not sign the server certificate fails", func(t *testing.T) {
		otherPEM := newTestCAPEM(t, "other-ca")
		err := get(otherPEM)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate signed by unknown authority")
	})
}

func TestHTTPTransport(t *testing.T) {
	t.Run("nil TLS config", func(t *testing.T) {
		var tlsConfig *TLSConfig
		transport, err := tlsConfig.HTTPTransport(http.DefaultTransport.(*http.Transport))
		assert.NoError(t, err)
		assert.NotNil(t, transport)

		// Should be default transport clone
		httpTransport, ok := transport.(*http.Transport)
		require.True(t, ok)
		assert.NotNil(t, httpTransport)
	})

	t.Run("skip verify config", func(t *testing.T) {
		tlsConfig := &TLSConfig{SkipVerify: true}
		transport, err := tlsConfig.HTTPTransport(http.DefaultTransport.(*http.Transport))
		assert.NoError(t, err)
		require.NotNil(t, transport)

		httpTransport, ok := transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, httpTransport.TLSClientConfig)
		assert.True(t, httpTransport.TLSClientConfig.InsecureSkipVerify)
	})

	t.Run("invalid TLS config", func(t *testing.T) {
		tlsConfig := &TLSConfig{
			CertFile: "nonexistent.pem",
			KeyFile:  "nonexistent.key",
		}
		_, err := tlsConfig.HTTPTransport(http.DefaultTransport.(*http.Transport))
		assert.Error(t, err)
	})
}

// mockRoundTripper is a mock implementation of http.RoundTripper for testing
type mockRoundTripper struct {
	capturedRequest *http.Request
	response        *http.Response
	err             error
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.capturedRequest = req
	if m.response != nil {
		return m.response, m.err
	}
	// Return a default successful response
	return &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}, m.err
}

func TestUserAgentTransport(t *testing.T) {
	tests := []struct {
		name              string
		userAgent         string
		existingUserAgent string
		expectedUserAgent string
	}{
		{
			name:              "sets user agent when not present",
			userAgent:         "mcp-grafana/1.0.0",
			existingUserAgent: "",
			expectedUserAgent: "mcp-grafana/1.0.0",
		},
		{
			name:              "does not override existing user agent",
			userAgent:         "mcp-grafana/1.0.0",
			existingUserAgent: "existing-client/2.0.0",
			expectedUserAgent: "existing-client/2.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock round tripper
			mockRT := &mockRoundTripper{}

			// Create user agent transport
			transport := &UserAgentTransport{
				rt:        mockRT,
				UserAgent: tt.userAgent,
			}

			// Create request
			req, err := http.NewRequest("GET", "http://example.com", nil)
			require.NoError(t, err)

			// Set existing user agent if specified
			if tt.existingUserAgent != "" {
				req.Header.Set("User-Agent", tt.existingUserAgent)
			}

			// Make request through transport
			_, err = transport.RoundTrip(req)
			require.NoError(t, err)

			// Verify user agent header
			assert.Equal(t, tt.expectedUserAgent, mockRT.capturedRequest.Header.Get("User-Agent"))
		})
	}
}

func TestVersion(t *testing.T) {
	version := Version()
	assert.NotEmpty(t, version)
	// Version should be either "(devel)" for development builds or a proper version
	assert.True(t, version == "(devel)" || len(version) > 0)
}

func TestUserAgent(t *testing.T) {
	userAgent := UserAgent()
	assert.Contains(t, userAgent, "mcp-grafana/")
	assert.NotEqual(t, "mcp-grafana/", userAgent) // Should have version appended

	// Should match the pattern mcp-grafana/{version}
	version := Version()
	expected := fmt.Sprintf("mcp-grafana/%s", version)
	assert.Equal(t, expected, userAgent)
}

func TestNewUserAgentTransport(t *testing.T) {
	t.Run("with explicit user agent", func(t *testing.T) {
		mockRT := &mockRoundTripper{}
		userAgent := "test-agent/1.0.0"

		transport := NewUserAgentTransport(mockRT, userAgent)

		assert.Equal(t, mockRT, transport.rt)
		assert.Equal(t, userAgent, transport.UserAgent)
	})

	t.Run("with default user agent", func(t *testing.T) {
		mockRT := &mockRoundTripper{}

		transport := NewUserAgentTransport(mockRT)

		assert.Equal(t, mockRT, transport.rt)
		assert.Equal(t, UserAgent(), transport.UserAgent)
		assert.Contains(t, transport.UserAgent, "mcp-grafana/")
	})
}

func TestNewUserAgentTransportWithNilRoundTripper(t *testing.T) {
	t.Run("with explicit user agent", func(t *testing.T) {
		userAgent := "test-agent/1.0.0"

		transport := NewUserAgentTransport(nil, userAgent)

		assert.Equal(t, http.DefaultTransport, transport.rt)
		assert.Equal(t, userAgent, transport.UserAgent)
	})

	t.Run("with default user agent", func(t *testing.T) {
		transport := NewUserAgentTransport(nil)

		assert.Equal(t, http.DefaultTransport, transport.rt)
		assert.Equal(t, UserAgent(), transport.UserAgent)
		assert.Contains(t, transport.UserAgent, "mcp-grafana/")
	})
}
