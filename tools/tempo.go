package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	mcpgrafana "github.com/grafana/mcp-grafana"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const (
	// Tag discovery goes through Grafana's datasource resource API; trace search
	// and trace fetch go through the datasource proxy. Both are UID-scoped in the
	// path, so neither needs the datasource type resolved first.
	tempoResourcesPath = "/api/datasources/uid/%s/resources"
	tempoProxyPath     = "/api/datasources/proxy/uid/%s"

	defaultTempoTagLimit    = 5000
	defaultTempoSearchLimit = 10
	// Tempo's search API has no default window, so an omitted range would scan
	// everything. Five minutes matches the window this tool has always used.
	defaultTempoSearchWindow = 5 * time.Minute

	tempoMaxAttempts    = 5
	tempoRetryBaseDelay = 1 * time.Second
	tempoRetryMaxDelay  = 8 * time.Second
)

// Statuses worth a second attempt: Tempo behind a loaded querier sheds load
// rather than failing outright.
var tempoRetryableStatuses = map[int]bool{
	http.StatusTooManyRequests:     true,
	http.StatusInternalServerError: true,
	http.StatusBadGateway:          true,
	http.StatusServiceUnavailable:  true,
	http.StatusGatewayTimeout:      true,
}

// tempoClient talks to Grafana, not to Tempo directly: BuildTransport carries the
// tenant's auth, private CA and connector dial-override from the request context.
type tempoClient struct {
	httpClient *http.Client
	baseURL    string
}

func newTempoClient(ctx context.Context) (*tempoClient, error) {
	cfg := mcpgrafana.GrafanaConfigFromContext(ctx)
	transport, err := mcpgrafana.BuildTransport(&cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport: %w", err)
	}
	return &tempoClient{
		httpClient: &http.Client{Transport: transport},
		baseURL:    strings.TrimRight(cfg.URL, "/"),
	}, nil
}

func (c *tempoClient) resourcesURL(uid, resource string, params url.Values) string {
	u := c.baseURL + fmt.Sprintf(tempoResourcesPath, url.PathEscape(uid)) + resource
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	return u
}

func (c *tempoClient) proxyURL(uid, path string, params url.Values) string {
	u := c.baseURL + fmt.Sprintf(tempoProxyPath, url.PathEscape(uid)) + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	return u
}

func (c *tempoClient) get(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	return c.httpClient.Do(req)
}

// getWithRetry is the same policy the gateway applied to trace search and trace
// fetch before these tools moved here: up to 5 attempts with exponential backoff
// (1s base, 8s cap), honouring Retry-After. A response that is still retryable on
// the final attempt is returned as-is, so the caller reports the real status.
func (c *tempoClient) getWithRetry(ctx context.Context, rawURL string) (*http.Response, error) {
	for attempt := 1; ; attempt++ {
		resp, err := c.get(ctx, rawURL)
		last := attempt >= tempoMaxAttempts

		if err == nil && (last || !tempoRetryableStatuses[resp.StatusCode]) {
			return resp, nil
		}
		if err != nil && last {
			return nil, err
		}

		delay := tempoBackoff(attempt)
		if err == nil {
			if retryAfter, ok := parseTempoRetryAfter(resp.Header.Get("Retry-After")); ok {
				delay = retryAfter
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
}

func tempoBackoff(attempt int) time.Duration {
	delay := tempoRetryBaseDelay << (attempt - 1)
	if delay > tempoRetryMaxDelay || delay <= 0 {
		return tempoRetryMaxDelay
	}
	return delay
}

// parseTempoRetryAfter reads both Retry-After forms: delay-seconds and HTTP-date.
func parseTempoRetryAfter(header string) (time.Duration, bool) {
	if header == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseFloat(header, 64); err == nil && seconds >= 0 {
		return time.Duration(seconds * float64(time.Second)), true
	}
	if at, err := http.ParseTime(header); err == nil {
		if delay := time.Until(at); delay > 0 {
			return delay, true
		}
		return 0, true
	}
	return 0, false
}

func decodeTempoResponse(resp *http.Response, operation string, target any) error {
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s failed: %s %s", operation, resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decoding %s response: %w", operation, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// fetch_tempo_tags
// ---------------------------------------------------------------------------

type FetchTempoTagsParams struct {
	DatasourceUID string `json:"datasourceUid" jsonschema:"required,description=The UID of the Tempo datasource to query"`
	Limit         int    `json:"limit,omitempty" jsonschema:"default=5000,description=Maximum number of tag names to return"`
}

type TempoTagScope struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type FetchTempoTagsResult struct {
	Scopes []TempoTagScope `json:"scopes,omitempty"`
}

func fetchTempoTags(ctx context.Context, args FetchTempoTagsParams) (*FetchTempoTagsResult, error) {
	client, err := newTempoClient(ctx)
	if err != nil {
		return nil, err
	}

	limit := args.Limit
	if limit <= 0 {
		limit = defaultTempoTagLimit
	}
	params := url.Values{"limit": {strconv.Itoa(limit)}}

	resp, err := client.get(ctx, client.resourcesURL(args.DatasourceUID, "/tags", params))
	if err != nil {
		return nil, fmt.Errorf("fetching Tempo tags: %w", err)
	}

	result := &FetchTempoTagsResult{}
	if err := decodeTempoResponse(resp, "fetching Tempo tags", result); err != nil {
		return nil, err
	}
	return result, nil
}

const fetchTempoTagsToolPrompt = `Fetches all available Tempo tag names from Grafana, grouped into scopes, to be used when constructing TraceQL filter expressions.

Returns a list of scopes, each containing the tag keys observable within that scope:
- "resource": Resource-level attributes attached to the service emitting the trace (e.g. service.name, deployment.environment, vcs.commit.hash, vcs.repository.fullName).
- "intrinsic": Built-in Tempo fields that describe trace/span structure (e.g. duration, status, kind, name, rootServiceName, span:status, trace:duration).
- "span": Span-level attributes capturing request semantics (e.g. http.method, http.route, http.status_code, db.system, db.statement, error.type, url.path).
- "event": Event-level attributes recorded within a span, typically exception details (e.g. exception.type, exception.message, exception.stacktrace, http.request.body).

Use this tool before constructing a TraceQL query to discover which tags are available in the target Tempo datasource. Reference tags from the "resource" scope with the resource. prefix (e.g. resource.service.name), tags from the "span" scope with the span. prefix (e.g. span.http.status_code), tags from the "event" scope with event. prefix, and intrinsic tags directly without a prefix (e.g. duration, status, name).

Example TraceQL expressions using these tags:
  { resource.service.name = "payments" && span.http.status_code >= 500 }
  { resource.deployment.environment = "production" && status = error }
  { span.http.method = "GET" || span.http.request.method = "GET" }
  { resource.vcs.repository.fullName = "org/repo" && span.db.system = "postgresql" }`

var FetchTempoTags = mcpgrafana.MustTool(
	"fetch_tempo_tags",
	fetchTempoTagsToolPrompt,
	fetchTempoTags,
	mcp.WithTitleAnnotation("Fetch Tempo tags"),
	mcp.WithIdempotentHintAnnotation(true),
	mcp.WithReadOnlyHintAnnotation(true),
)

// ---------------------------------------------------------------------------
// fetch_tempo_tag_values
// ---------------------------------------------------------------------------

type FetchTempoTagValuesParams struct {
	DatasourceUID string `json:"datasourceUid" jsonschema:"required,description=The UID of the Tempo datasource to query"`
	Tag           string `json:"tag" jsonschema:"required,description=Tempo tag key to fetch values for\\, for example span.http.method. Reference tags from the \"resource\" scope with the resource. prefix (e.g. resource.service.name)\\, tags from the \"span\" scope with the span. prefix (e.g. span.http.status_code)\\, tags from the \"event\" scope with the event. prefix\\, and intrinsic tags directly without a prefix (e.g. duration\\, status\\, name)."`
}

type TempoTagValue struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type FetchTempoTagValuesResult struct {
	TagValues []TempoTagValue `json:"tagValues,omitempty"`
}

func fetchTempoTagValues(ctx context.Context, args FetchTempoTagValuesParams) (*FetchTempoTagValuesResult, error) {
	if strings.TrimSpace(args.Tag) == "" {
		return nil, fmt.Errorf("tag is required")
	}

	client, err := newTempoClient(ctx)
	if err != nil {
		return nil, err
	}

	params := url.Values{"tag": {args.Tag}}
	resp, err := client.get(ctx, client.resourcesURL(args.DatasourceUID, "/tag-values", params))
	if err != nil {
		return nil, fmt.Errorf("fetching Tempo tag values for %q: %w", args.Tag, err)
	}

	result := &FetchTempoTagValuesResult{}
	if err := decodeTempoResponse(resp, fmt.Sprintf("fetching Tempo tag values for %q", args.Tag), result); err != nil {
		return nil, err
	}
	return result, nil
}

var FetchTempoTagValues = mcpgrafana.MustTool(
	"fetch_tempo_tag_values",
	"Fetches the observed values for a specific Tempo tag from Grafana. Use this after discovering an available tag key when you need concrete values to build or refine a TraceQL filter.",
	fetchTempoTagValues,
	mcp.WithTitleAnnotation("Fetch Tempo tag values"),
	mcp.WithIdempotentHintAnnotation(true),
	mcp.WithReadOnlyHintAnnotation(true),
)

// ---------------------------------------------------------------------------
// search_tempo_traces
// ---------------------------------------------------------------------------

type SearchTempoTracesParams struct {
	DatasourceUID string `json:"datasourceUid" jsonschema:"required,description=The UID of the Tempo datasource to query"`
	Query         string `json:"query" jsonschema:"required,description=The TraceQL query to execute against Tempo"`
	StartRFC3339  string `json:"startRfc3339,omitempty" jsonschema:"description=Optionally\\, the start time of the search in RFC3339 format or relative time (e.g. 'now-1h') (defaults to 5 minutes ago)"`
	EndRFC3339    string `json:"endRfc3339,omitempty" jsonschema:"description=Optionally\\, the end time of the search in RFC3339 format or relative time (e.g. 'now') (defaults to now)"`
	Limit         int    `json:"limit,omitempty" jsonschema:"default=10,description=Optionally\\, the maximum number of traces to return"`
}

type TempoTraceSummary struct {
	TraceID           string `json:"traceID"`
	RootServiceName   string `json:"rootServiceName,omitempty"`
	RootTraceName     string `json:"rootTraceName,omitempty"`
	StartTimeUnixNano string `json:"startTimeUnixNano,omitempty"`
	DurationMs        int64  `json:"durationMs,omitempty"`
}

type SearchTempoTracesResult struct {
	Traces []TempoTraceSummary `json:"traces"`
}

func searchTempoTraces(ctx context.Context, args SearchTempoTracesParams) (*SearchTempoTracesResult, error) {
	if strings.TrimSpace(args.Query) == "" {
		return nil, fmt.Errorf("query is required")
	}

	start, err := parseStartTime(args.StartRFC3339)
	if err != nil {
		return nil, fmt.Errorf("parsing start time: %w", err)
	}
	end, err := parseEndTime(args.EndRFC3339)
	if err != nil {
		return nil, fmt.Errorf("parsing end time: %w", err)
	}
	now := time.Now()
	if end.IsZero() {
		end = now
	}
	if start.IsZero() {
		start = now.Add(-defaultTempoSearchWindow)
	}

	limit := args.Limit
	if limit <= 0 {
		limit = defaultTempoSearchLimit
	}

	client, err := newTempoClient(ctx)
	if err != nil {
		return nil, err
	}

	params := url.Values{
		"q":     {args.Query},
		"limit": {strconv.Itoa(limit)},
		"start": {strconv.FormatInt(start.Unix(), 10)},
		"end":   {strconv.FormatInt(end.Unix(), 10)},
	}

	resp, err := client.getWithRetry(ctx, client.proxyURL(args.DatasourceUID, "/api/search", params))
	if err != nil {
		return nil, fmt.Errorf("searching Tempo traces: %w", err)
	}

	var body struct {
		Traces []TempoTraceSummary `json:"traces"`
	}
	if err := decodeTempoResponse(resp, "searching Tempo traces", &body); err != nil {
		return nil, err
	}

	// Tempo can repeat a trace across search blocks; keep the first hit for each
	// ID so the agent is not handed the same trace twice.
	seen := make(map[string]bool, len(body.Traces))
	traces := make([]TempoTraceSummary, 0, len(body.Traces))
	for _, trace := range body.Traces {
		if seen[trace.TraceID] {
			continue
		}
		seen[trace.TraceID] = true
		traces = append(traces, trace)
	}

	return &SearchTempoTracesResult{Traces: traces}, nil
}

var SearchTempoTraces = mcpgrafana.MustTool(
	"search_tempo_traces",
	"Searches Grafana Tempo traces with a TraceQL query over a time range and returns matching trace summaries. If the time range is not provided, it defaults to the last 5 minutes.",
	searchTempoTraces,
	mcp.WithTitleAnnotation("Search Tempo traces"),
	mcp.WithIdempotentHintAnnotation(true),
	mcp.WithReadOnlyHintAnnotation(true),
)

// ---------------------------------------------------------------------------
// fetch_tempo_trace
// ---------------------------------------------------------------------------

type FetchTempoTraceParams struct {
	DatasourceUID string `json:"datasourceUid" jsonschema:"required,description=The UID of the Tempo datasource to query"`
	TraceID       string `json:"traceId" jsonschema:"required,description=The Tempo trace ID to fetch"`
	StartRFC3339  string `json:"startRfc3339,omitempty" jsonschema:"description=Optionally\\, the start of the window to look for the trace in\\, in RFC3339 format or relative time (e.g. 'now-1h')"`
	EndRFC3339    string `json:"endRfc3339,omitempty" jsonschema:"description=Optionally\\, the end of the window to look for the trace in\\, in RFC3339 format or relative time (e.g. 'now')"`
}

// FetchTempoTraceResult carries the OTLP payload through untouched — the span
// tree is what the agent reads, and reshaping it here would only lose fields.
type FetchTempoTraceResult struct {
	Trace json.RawMessage `json:"trace"`
}

func fetchTempoTrace(ctx context.Context, args FetchTempoTraceParams) (*FetchTempoTraceResult, error) {
	if strings.TrimSpace(args.TraceID) == "" {
		return nil, fmt.Errorf("traceId is required")
	}

	start, err := parseStartTime(args.StartRFC3339)
	if err != nil {
		return nil, fmt.Errorf("parsing start time: %w", err)
	}
	end, err := parseEndTime(args.EndRFC3339)
	if err != nil {
		return nil, fmt.Errorf("parsing end time: %w", err)
	}

	client, err := newTempoClient(ctx)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	if !start.IsZero() {
		params.Set("start", strconv.FormatInt(start.Unix(), 10))
	}
	if !end.IsZero() {
		params.Set("end", strconv.FormatInt(end.Unix(), 10))
	}

	path := "/api/v2/traces/" + url.PathEscape(args.TraceID)
	resp, err := client.getWithRetry(ctx, client.proxyURL(args.DatasourceUID, path, params))
	if err != nil {
		return nil, fmt.Errorf("fetching Tempo trace %s: %w", args.TraceID, err)
	}

	// A trace outside the queried window, or already past retention, is a normal
	// outcome rather than a failure — report it as an empty trace.
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		return &FetchTempoTraceResult{}, nil
	}

	result := &FetchTempoTraceResult{}
	if err := decodeTempoResponse(resp, fmt.Sprintf("fetching Tempo trace %s", args.TraceID), &result.Trace); err != nil {
		return nil, err
	}
	return result, nil
}

var FetchTempoTrace = mcpgrafana.MustTool(
	"fetch_tempo_trace",
	"Fetches a full raw Tempo trace payload from Grafana for a specific trace ID. Use this after trace search when you need span-level details and events. Returns an empty trace when the ID is not found in the queried window.",
	fetchTempoTrace,
	mcp.WithTitleAnnotation("Fetch Tempo trace"),
	mcp.WithIdempotentHintAnnotation(true),
	mcp.WithReadOnlyHintAnnotation(true),
)

// AddTempoTools registers all Tempo tools with the MCP server
func AddTempoTools(mcp *server.MCPServer) {
	FetchTempoTags.Register(mcp)
	FetchTempoTagValues.Register(mcp)
	SearchTempoTraces.Register(mcp)
	FetchTempoTrace.Register(mcp)
}
