package mcpgrafana

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/grafana/incident-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientCache_GrafanaClient(t *testing.T) {
	cache := NewClientCache(nil)
	defer cache.Close()

	key := clientCacheKey{url: "http://localhost:3000", apiKey: "test-key", orgID: 1}
	createCount := 0

	createFn := func() *GrafanaClient {
		createCount++
		return &GrafanaClient{}
	}

	// First call should create
	client1 := cache.GetOrCreateGrafanaClient(key, createFn)
	require.NotNil(t, client1)
	assert.Equal(t, 1, createCount)

	// Second call with same key should return cached
	client2 := cache.GetOrCreateGrafanaClient(key, createFn)
	assert.Same(t, client1, client2)
	assert.Equal(t, 1, createCount, "createFn should not be called again for same key")

	// Different key should create new client
	key2 := clientCacheKey{url: "http://other:3000", apiKey: "other-key", orgID: 2}
	client3 := cache.GetOrCreateGrafanaClient(key2, createFn)
	require.NotNil(t, client3)
	assert.NotSame(t, client1, client3)
	assert.Equal(t, 2, createCount)

	g, _, _ := cache.Size()
	assert.Equal(t, 2, g)
}

func TestClientCache_IncidentClient(t *testing.T) {
	cache := NewClientCache(nil)
	defer cache.Close()

	key := clientCacheKey{url: "http://localhost:3000", apiKey: "test-key", orgID: 1}
	createCount := 0

	createFn := func() *incident.Client {
		createCount++
		return incident.NewClient("http://localhost:3000/api/plugins/grafana-irm-app/resources/api/v1/", "test-key")
	}

	client1 := cache.GetOrCreateIncidentClient(key, createFn)
	require.NotNil(t, client1)
	assert.Equal(t, 1, createCount)

	client2 := cache.GetOrCreateIncidentClient(key, createFn)
	assert.Same(t, client1, client2)
	assert.Equal(t, 1, createCount)

	_, i, _ := cache.Size()
	assert.Equal(t, 1, i)
}

func TestClientCache_ConcurrentAccess(t *testing.T) {
	cache := NewClientCache(nil)
	defer cache.Close()

	key := clientCacheKey{url: "http://localhost:3000", apiKey: "test-key", orgID: 1}

	var mu sync.Mutex
	createCount := 0

	createFn := func() *GrafanaClient {
		mu.Lock()
		createCount++
		mu.Unlock()
		return &GrafanaClient{}
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	clients := make([]*GrafanaClient, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			clients[idx] = cache.GetOrCreateGrafanaClient(key, createFn)
		}(i)
	}
	wg.Wait()

	// All goroutines should get the same client
	for i := 1; i < numGoroutines; i++ {
		assert.Same(t, clients[0], clients[i], "All goroutines should get the same cached client")
	}

	// createFn should be called exactly once
	assert.Equal(t, 1, createCount, "Client should be created exactly once")
}

func TestClientCache_DifferentCredentials(t *testing.T) {
	cache := NewClientCache(nil)
	defer cache.Close()

	keys := []clientCacheKey{
		{url: "http://host1:3000", apiKey: "key1", orgID: 1, forwardedHeaders: "X-WEBAUTH-USER=admin"},    // base key
		{url: "http://host1:3000", apiKey: "key2", orgID: 1, forwardedHeaders: "X-WEBAUTH-USER=admin"},    // different key
		{url: "http://host1:3000", apiKey: "key1", orgID: 2, forwardedHeaders: "X-WEBAUTH-USER=admin"},    // different org
		{url: "http://host2:3000", apiKey: "key1", orgID: 1, forwardedHeaders: "X-WEBAUTH-USER=admin"},    // different url
		{url: "http://host1:3000", apiKey: "key1", orgID: 1, forwardedHeaders: "X-WEBAUTH-USER=admin"},    // same as first
		{url: "http://host1:3000", apiKey: "key1", orgID: 1, forwardedHeaders: "X-WEBAUTH-USER=john.doe"}, // different user
	}

	const numUniqueKeys = 5

	clients := make([]*GrafanaClient, len(keys))
	for i, key := range keys {
		clients[i] = cache.GetOrCreateGrafanaClient(key, func() *GrafanaClient {
			return &GrafanaClient{}
		})
	}

	// First and last should be the same (same key)
	assert.Same(t, clients[0], clients[4])
	// All others should be different
	assert.NotSame(t, clients[0], clients[1])
	assert.NotSame(t, clients[0], clients[2])
	assert.NotSame(t, clients[0], clients[3])
	assert.NotSame(t, clients[0], clients[5])

	g, _, _ := cache.Size()
	assert.Equal(t, numUniqueKeys, g) // 5 unique keys
}

func TestCacheKeyFromRequest(t *testing.T) {
	key1 := cacheKeyFromRequest("http://localhost:3000", "key1", nil, 1, "", "", nil)
	key2 := cacheKeyFromRequest("http://localhost:3000", "key1", nil, 1, "", "", nil)
	assert.Equal(t, key1, key2)

	key3 := cacheKeyFromRequest("http://localhost:3000", "key1", url.UserPassword("admin", "pass"), 1, "", "", nil)
	assert.NotEqual(t, key1, key3)

	assert.Equal(t, "admin", key3.username)
	assert.Equal(t, "pass", key3.password)
}

func TestClientCache_Close(t *testing.T) {
	cache := NewClientCache(nil)

	key := clientCacheKey{url: "http://localhost:3000", apiKey: "key", orgID: 1}
	cache.GetOrCreateGrafanaClient(key, func() *GrafanaClient {
		return &GrafanaClient{}
	})
	cache.GetOrCreateIncidentClient(key, func() *incident.Client {
		return incident.NewClient("http://localhost:3000/incident", "key")
	})

	g, i, _ := cache.Size()
	assert.Equal(t, 1, g)
	assert.Equal(t, 1, i)

	cache.Close()

	g, i, _ = cache.Size()
	assert.Equal(t, 0, g)
	assert.Equal(t, 0, i)
}

func TestCacheKeyIncludesDialAddr(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost", nil)
	require.NoError(t, err)

	k1 := cacheKeyFromRequest("http://grafana.internal", "key", nil, 0, "127.0.0.1:39001", "", req)
	k2 := cacheKeyFromRequest("http://grafana.internal", "key", nil, 0, "127.0.0.1:39002", "", req)
	k3 := cacheKeyFromRequest("http://grafana.internal", "key", nil, 0, "127.0.0.1:39001", "", req)

	require.NotEqual(t, k1, k2, "different dial addrs must produce different cache keys")
	require.Equal(t, k1, k3, "same dial addr must produce the same cache key")
}

func TestCacheKeyIncludesCAPem(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost", nil)
	require.NoError(t, err)

	const caA = "-----BEGIN CERTIFICATE-----\ntenant-a\n-----END CERTIFICATE-----\n"
	const caB = "-----BEGIN CERTIFICATE-----\ntenant-b\n-----END CERTIFICATE-----\n"

	k1 := cacheKeyFromRequest("http://grafana.internal", "key", nil, 0, "", caA, req)
	k2 := cacheKeyFromRequest("http://grafana.internal", "key", nil, 0, "", caB, req)
	k3 := cacheKeyFromRequest("http://grafana.internal", "key", nil, 0, "", caA, req)
	k4 := cacheKeyFromRequest("http://grafana.internal", "key", nil, 0, "", "", req)

	require.NotEqual(t, k1, k2, "different CA bundles must produce different cache keys")
	require.Equal(t, k1, k3, "same CA bundle must produce the same cache key")
	require.NotEqual(t, k1, k4, "a CA bundle must not share a key with no CA bundle")
	require.NotContains(t, k1.caPemHash, "tenant-a", "the key must carry a hash, not the PEM itself")
	require.Empty(t, k4.caPemHash)
}

func TestClientCacheSeparatesTenantsByCAPem(t *testing.T) {
	// Same URL and same token, different private CAs. A cached client is bound to
	// the trust configuration it was built with, so the two tenants must not share
	// one — otherwise tenant B silently inherits tenant A's trust config.
	ts := newTestHTTPServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})

	cache := NewClientCache(nil)
	defer cache.Close()
	extract := extractGrafanaClientCached(cache)

	clientFor := func(caPem string) *GrafanaClient {
		req, err := http.NewRequest("GET", "http://localhost", nil)
		require.NoError(t, err)
		req.Header.Set(grafanaURLHeader, ts.URL)
		req.Header.Set(grafanaServiceAccountTokenHeader, "shared-token")
		req.Header.Set(grafanaCAPemHeader, base64.StdEncoding.EncodeToString([]byte(caPem)))

		ctx := ExtractGrafanaInfoFromHeaders(context.Background(), req)
		return GrafanaClientFromContext(extract(ctx, req))
	}

	caA := newTestCAPEM(t, "tenant-a-ca")
	caB := newTestCAPEM(t, "tenant-b-ca")

	clientA := clientFor(caA)
	clientB := clientFor(caB)
	clientA2 := clientFor(caA)

	require.NotNil(t, clientA)
	require.NotNil(t, clientB)
	require.NotSame(t, clientA, clientB, "tenants with different CAs must not share a cached client")
	require.Same(t, clientA, clientA2, "the same CA must still hit the cache")

	g, _, _ := cache.Size()
	require.Equal(t, 2, g)
}
