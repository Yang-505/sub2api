//go:build unit

package ip

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestGetTrustedClientIPUsesGinClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	require.NoError(t, r.SetTrustedProxies(nil))

	r.GET("/t", func(c *gin.Context) {
		c.String(200, GetTrustedClientIP(c))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = "9.9.9.9:12345"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	req.Header.Set("CF-Connecting-IP", "1.2.3.4")
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	require.Equal(t, "9.9.9.9", w.Body.String())
}

func TestGetClientIPRejectsUntrustedDockerForwardedHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	require.NoError(t, r.SetTrustedProxies(nil))
	r.GET("/t", func(c *gin.Context) {
		c.String(200, GetClientIP(c))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = "192.168.32.1:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.2, 203.0.113.42")
	req.Header.Set("X-Real-IP", "192.168.32.1")
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	require.Equal(t, "192.168.32.1", w.Body.String())
}

func TestCheckIPRestrictionWithCompiledRules(t *testing.T) {
	whitelist := CompileIPRules([]string{"10.0.0.0/8", "192.168.1.2"})
	blacklist := CompileIPRules([]string{"10.1.1.1"})

	allowed, reason := CheckIPRestrictionWithCompiledRules("10.2.3.4", whitelist, blacklist)
	require.True(t, allowed)
	require.Equal(t, "", reason)

	allowed, reason = CheckIPRestrictionWithCompiledRules("10.1.1.1", whitelist, blacklist)
	require.False(t, allowed)
	require.Equal(t, "access denied", reason)
}

func TestCheckIPRestrictionWithCompiledRules_InvalidWhitelistStillDenies(t *testing.T) {
	// 与旧实现保持一致：白名单有配置但全无效时，最终应拒绝访问。
	invalidWhitelist := CompileIPRules([]string{"not-a-valid-pattern"})
	allowed, reason := CheckIPRestrictionWithCompiledRules("8.8.8.8", invalidWhitelist, nil)
	require.False(t, allowed)
	require.Equal(t, "access denied", reason)
}

func TestGetSecurityClientIPSwitchCannotBypassProxyTrust(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	require.NoError(t, r.SetTrustedProxies(nil))
	r.GET("/t", func(c *gin.Context) {
		c.String(200, GetSecurityClientIP(c, true))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = "9.9.9.9:12345"
	req.Header.Set("X-Real-IP", "1.2.3.4")
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	require.Equal(t, "9.9.9.9", w.Body.String())
}

func TestGetSecurityClientIPCustomHeaderPrecedenceAndFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		trustForward   bool
		headers        []string
		requestHeaders map[string]string
		want           string
	}{
		{
			name:         "configured order precedes built-ins",
			trustForward: true,
			headers:      []string{"X-CDN-First", "X-CDN-Second"},
			requestHeaders: map[string]string{
				"X-CDN-First":      "198.51.100.10",
				"X-CDN-Second":     "203.0.113.20",
				"CF-Connecting-IP": "8.8.8.8",
			},
			want: "198.51.100.10",
		},
		{
			name:         "invalid custom chains are rejected entirely",
			trustForward: true,
			headers:      []string{"X-CDN-First", "X-CDN-Second"},
			requestHeaders: map[string]string{
				"X-CDN-First":  "not-an-ip, 10.0.0.8",
				"X-CDN-Second": "also-bad, 203.0.113.9",
			},
			want: "9.9.9.9",
		},
		{
			name:         "valid private client retains custom header precedence",
			trustForward: true,
			headers:      []string{"X-CDN-IP"},
			requestHeaders: map[string]string{
				"X-CDN-IP":  "10.0.0.8",
				"X-Real-IP": "1.2.3.4",
			},
			want: "10.0.0.8",
		},
		{
			name:         "custom private client retains configured precedence",
			trustForward: true,
			headers:      []string{"X-CDN-IP"},
			requestHeaders: map[string]string{
				"X-CDN-IP":  "10.0.0.8",
				"X-Real-IP": "192.168.1.4",
			},
			want: "10.0.0.8",
		},
		{
			name:         "invalid custom value continues to built-ins",
			trustForward: true,
			headers:      []string{"X-CDN-IP"},
			requestHeaders: map[string]string{
				"X-CDN-IP":         "1.2.3.4:443",
				"CF-Connecting-IP": "4.4.4.4",
			},
			want: "4.4.4.4",
		},
		{
			name:         "invalid standard chain falls back to connection address",
			trustForward: true,
			requestHeaders: map[string]string{
				"CF-Connecting-IP": "unknown",
				"X-Real-IP":        "proxy.internal",
				"X-Forwarded-For":  "also-invalid, 203.0.113.50",
			},
			want: "9.9.9.9",
		},
		{
			name:         "all invalid legacy values fall back to the connection address",
			trustForward: true,
			requestHeaders: map[string]string{
				"CF-Connecting-IP": "unknown",
				"X-Real-IP":        "proxy.internal",
				"X-Forwarded-For":  "also-invalid",
			},
			want: "9.9.9.9",
		},
		{
			name:         "disabled mode ignores custom and legacy headers",
			trustForward: false,
			headers:      []string{"X-CDN-IP"},
			requestHeaders: map[string]string{
				"X-CDN-IP":  "1.2.3.4",
				"X-Real-IP": "4.4.4.4",
			},
			want: "9.9.9.9",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := gin.New()
			require.NoError(t, r.SetTrustedProxies(nil))
			r.GET("/t", func(c *gin.Context) {
				var proxyPatterns []string
				if test.trustForward {
					proxyPatterns = []string{"9.9.9.9"}
				}
				SetForwardedIPSettings(c, test.trustForward, test.headers, CompileIPRules(proxyPatterns))
				c.String(200, GetSecurityClientIP(c, !test.trustForward))
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/t", nil)
			req.RemoteAddr = "9.9.9.9:12345"
			for name, value := range test.requestHeaders {
				req.Header.Set(name, value)
			}
			r.ServeHTTP(w, req)

			require.Equal(t, test.want, w.Body.String())
		})
	}
}

func TestGetSecurityClientIPSwitchDisabledUsesConfiguredTrustedProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	require.NoError(t, r.SetTrustedProxies([]string{"9.9.9.9"}))
	r.GET("/t", func(c *gin.Context) { c.String(200, GetSecurityClientIP(c, false)) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = "9.9.9.9:12345"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.ServeHTTP(w, req)

	require.Equal(t, "1.2.3.4", w.Body.String())
}

func TestGetClientIPSwitchDisabledUsesTrustedProxyChain(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	require.NoError(t, r.SetTrustedProxies(nil))
	r.GET("/t", func(c *gin.Context) {
		SetLegacyForwardedIPTrust(c, false)
		c.String(200, GetClientIP(c))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = "9.9.9.9:12345"
	req.Header.Set("X-Real-IP", "1.2.3.4")
	r.ServeHTTP(w, req)

	require.Equal(t, "9.9.9.9", w.Body.String())
}

func TestGetSecurityClientIPRequestSnapshotCopiesCustomHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	require.NoError(t, r.SetTrustedProxies(nil))
	r.GET("/t", func(c *gin.Context) {
		headers := []string{"X-Original-IP"}
		SetForwardedIPSettings(c, true, headers, CompileIPRules([]string{"9.9.9.9"}))
		headers[0] = "X-Mutated-IP"
		c.Request.Header.Set("X-Original-IP", "8.8.8.8")
		c.String(200, GetSecurityClientIP(c, false))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = "9.9.9.9:12345"
	req.Header.Set("X-Original-IP", "1.2.3.4")
	req.Header.Set("X-Mutated-IP", "4.4.4.4")
	r.ServeHTTP(w, req)

	require.Equal(t, "1.2.3.4", w.Body.String())
}

func TestGetSecurityClientIPRequestSnapshotOverridesLiveFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		requestTrust  bool
		fallbackTrust bool
		want          string
	}{
		{name: "captured secure mode wins", requestTrust: false, fallbackTrust: true, want: "9.9.9.9"},
		{name: "captured compatibility mode wins", requestTrust: true, fallbackTrust: false, want: "1.2.3.4"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := gin.New()
			require.NoError(t, r.SetTrustedProxies(nil))
			r.GET("/t", func(c *gin.Context) {
				SetForwardedIPSettings(c, test.requestTrust, nil, CompileIPRules([]string{"9.9.9.9"}))
				c.String(200, GetSecurityClientIP(c, test.fallbackTrust))
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/t", nil)
			req.RemoteAddr = "9.9.9.9:12345"
			req.Header.Set("CF-Connecting-IP", "1.2.3.4")
			r.ServeHTTP(w, req)

			require.Equal(t, test.want, w.Body.String())
		})
	}
}

// TestClientIPResolutionTrustBoundary 覆盖直连伪造、代理链注入、重复头和 IPv6 的安全边界。
func TestClientIPResolutionTrustBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name         string
		proxies      []string
		peer         string
		custom       []string
		standardOnly bool
		headers      map[string][]string
		wantIP       string
		wantSource   string
	}{
		{
			name: "unconfigured policy ignores all spoofed headers", peer: "9.9.9.9:1234",
			custom: []string{"X-CDN-IP"}, headers: map[string][]string{
				"X-CDN-IP": {"1.2.3.4"}, "CF-Connecting-IP": {"2.2.2.2"},
				"X-Real-IP": {"3.3.3.3"}, "X-Forwarded-For": {"4.4.4.4"},
			}, wantIP: "9.9.9.9", wantSource: "remote_addr",
		},
		{
			name: "untrusted peer cannot impersonate CF", proxies: []string{"10.0.0.2"}, peer: "9.9.9.9:1234",
			headers: map[string][]string{"CF-Connecting-IP": {"1.2.3.4"}}, wantIP: "9.9.9.9", wantSource: "remote_addr",
		},
		{
			name: "trusted proxy supplies CF client", proxies: []string{"10.0.0.2"}, peer: "10.0.0.2:443",
			headers: map[string][]string{"CF-Connecting-IP": {"203.0.113.42"}}, wantIP: "203.0.113.42", wantSource: "header:cf-connecting-ip",
		},
		{
			name: "standard mode ignores CF headers", proxies: []string{"10.0.0.2"}, peer: "10.0.0.2:443", standardOnly: true,
			headers: map[string][]string{"CF-Connecting-IP": {"1.2.3.4"}, "X-Forwarded-For": {"203.0.113.42"}},
			wantIP:  "203.0.113.42", wantSource: "header:x-forwarded-for",
		},
		{
			name: "injected leftmost XFF does not override real client", proxies: []string{"10.0.0.2", "10.0.0.3"}, peer: "10.0.0.2:443",
			headers: map[string][]string{"X-Forwarded-For": {"1.2.3.4, 203.0.113.42, 10.0.0.3"}},
			wantIP:  "203.0.113.42", wantSource: "header:x-forwarded-for",
		},
		{
			name: "chain stops at an untrusted intermediate proxy", proxies: []string{"10.0.0.2"}, peer: "10.0.0.2:443",
			headers: map[string][]string{"X-Forwarded-For": {"1.2.3.4, 10.0.0.3"}}, wantIP: "10.0.0.3", wantSource: "header:x-forwarded-for",
		},
		{
			name: "custom chain uses the same trust boundary", proxies: []string{"10.0.0.2"}, peer: "10.0.0.2:443", custom: []string{"X-CDN-IP"},
			headers: map[string][]string{"X-CDN-IP": {"1.2.3.4, 203.0.113.42"}}, wantIP: "203.0.113.42", wantSource: "header:x-cdn-ip",
		},
		{
			name: "duplicate CF values fall back to valid chain", proxies: []string{"10.0.0.2"}, peer: "10.0.0.2:443",
			headers: map[string][]string{"CF-Connecting-IP": {"1.2.3.4", "2.2.2.2"}, "X-Forwarded-For": {"203.0.113.42"}},
			wantIP:  "203.0.113.42", wantSource: "header:x-forwarded-for",
		},
		{
			name: "CF lists and real IP ports are invalid", proxies: []string{"10.0.0.2"}, peer: "10.0.0.2:443",
			headers: map[string][]string{"CF-Connecting-IP": {"1.2.3.4, 2.2.2.2"}, "X-Real-IP": {"3.3.3.3:80"}},
			wantIP:  "10.0.0.2", wantSource: "remote_addr",
		},
		{
			name: "invalid chain is not partially accepted", proxies: []string{"10.0.0.2"}, peer: "10.0.0.2:443",
			headers: map[string][]string{"X-Forwarded-For": {"unknown, 203.0.113.42"}}, wantIP: "10.0.0.2", wantSource: "remote_addr",
		},
		{
			name: "IPv6 proxy and client are normalized", proxies: []string{"2001:db8:1::/64"}, peer: "[2001:db8:1::2]:443",
			headers: map[string][]string{"CF-Connecting-IP": {"2001:0db8:2::3"}}, wantIP: "2001:db8:2::3", wantSource: "header:cf-connecting-ip",
		},
		{
			name: "IPv4 mapped peer matches IPv4 trust rules", proxies: []string{"10.0.0.2"}, peer: "[::ffff:10.0.0.2]:443",
			headers: map[string][]string{"CF-Connecting-IP": {"203.0.113.42"}}, wantIP: "203.0.113.42", wantSource: "header:cf-connecting-ip",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			require.NoError(t, r.SetTrustedProxies(nil))
			r.GET("/t", func(c *gin.Context) {
				SetForwardedIPSettings(c, !tc.standardOnly, tc.custom, CompileIPRules(tc.proxies))
				resolution := GetClientIPResolution(c)
				require.Equal(t, tc.wantIP, resolution.ClientIP)
				require.Equal(t, normalizeValidIP(tc.peer), resolution.PeerIP)
				require.Equal(t, tc.wantSource, resolution.Source)
				require.Equal(t, tc.wantIP, GetSecurityClientIP(c, tc.standardOnly))
				c.Status(200)
			})
			request := httptest.NewRequest("GET", "/t", nil)
			request.RemoteAddr = tc.peer
			for header, values := range tc.headers {
				for _, value := range values {
					request.Header.Add(header, value)
				}
			}
			recorder := httptest.NewRecorder()
			r.ServeHTTP(recorder, request)
			require.Equal(t, 200, recorder.Code)
		})
	}
}
