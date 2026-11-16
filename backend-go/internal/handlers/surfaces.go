package handlers

// Where each API operation can be reached besides the API itself: the UI,
// the spm command (cli) and the MCP server. The API is the one every surface
// calls, so the UI, the command and the MCP server do what it does, under the
// same names and with the same answers.
//
// The entries are checked, not trusted:
//   - TestEveryOperationSaysWhereItIsReached: every operation has an entry
//     and no entry names an operation that does not exist;
//   - ui/src/surfaces.test.ts: the operations marked ui are exactly the ones
//     the UI source calls;
//   - tests/python/test_mcp_surfaces.py: the operations marked mcp are
//     exactly the ones the MCP tools call.
//
// Every operation carries a decision, and TestEveryOperationSaysWhereItIsReached
// fails on one that does not:
//   - apiOnly: it belongs to the API alone, with the reason (a probe, a call
//     the WAF makes, a retired route);
//   - notInUI: the dashboard deliberately does not offer it, with the reason;
//     the command and the MCP server are where it goes;
//   - uiPlanned: the dashboard is to offer it and does not yet. The UI test
//     fails once the dashboard calls it, so the flag cannot outlive the work.
//
// The published document carries x-spm-surfaces, x-spm-api-only,
// x-spm-not-in-ui, and for the MCP tools x-spm-mcp-name and x-spm-untrusted.

type surfaceSet struct {
	ui        bool
	cli       bool
	mcp       bool
	apiOnly   string
	notInUI   string
	uiPlanned bool
	// mcpName is the MCP tool's name, set exactly when mcp is: the MCP server
	// builds its tools from the published document (x-spm-mcp-name).
	mcpName string
	// untrusted: the answer carries what clients of the proxy can shape
	// (URLs, hosts, user agents, entries read from third-party feeds), so the
	// MCP server marks it as data, not instructions (x-spm-untrusted).
	untrusted bool
}

// names lists the surfaces besides the API, in a fixed order.
func (s surfaceSet) names() []string {
	out := []string{"api"}
	if s.ui {
		out = append(out, "ui")
	}
	if s.cli {
		out = append(out, "cli")
	}
	if s.mcp {
		out = append(out, "mcp")
	}
	return out
}

// routeSurfaces is keyed by method and OpenAPI path, as docs/public/openapi.json names them.
var routeSurfaces = map[string]surfaceSet{
	"DELETE /api/client-groups/{id}":               {ui: true},
	"DELETE /api/domain-blacklist/clear-all":       {ui: true, cli: true},
	"DELETE /api/domain-blacklist/sources/{id}":    {ui: true},
	"DELETE /api/domain-blacklist/{id}":            {ui: true, cli: true, mcp: true, mcpName: "spm_unblock_domain"},
	"DELETE /api/domain-whitelist/clear-all":       {ui: true, cli: true},
	"DELETE /api/domain-whitelist/sources/{id}":    {ui: true},
	"DELETE /api/domain-whitelist/{id}":            {ui: true, cli: true},
	"DELETE /api/egress-allowlist/clear-all":       {ui: true, cli: true},
	"DELETE /api/egress-allowlist/{id}":            {ui: true, cli: true},
	"DELETE /api/egress-providers/url/{id}":        {ui: true},
	"DELETE /api/ip-blacklist/clear-all":           {ui: true, cli: true},
	"DELETE /api/ip-blacklist/sources/{id}":        {ui: true},
	"DELETE /api/ip-blacklist/{id}":                {ui: true, cli: true},
	"DELETE /api/ip-whitelist/clear-all":           {ui: true, cli: true},
	"DELETE /api/ip-whitelist/sources/{id}":        {ui: true},
	"DELETE /api/ip-whitelist/{id}":                {ui: true, cli: true},
	"DELETE /api/security/rate-limits/{ip}":        {ui: true, cli: true},
	"DELETE /api/tokens/{id}":                      {ui: true},
	"GET /api/analytics/blocked-by-day":            {ui: true},
	"GET /api/analytics/cache-by-day":              {ui: true},
	"GET /api/analytics/coverage":                  {ui: true},
	"GET /api/analytics/file-extensions":           {ui: true},
	"GET /api/analytics/shadow-it":                 {ui: true, mcp: true, mcpName: "spm_shadow_it", untrusted: true},
	"GET /api/analytics/top-destinations":          {ui: true, mcp: true, mcpName: "spm_top_domains", untrusted: true},
	"GET /api/analytics/top-domains":               {apiOnly: "retired: it answers 410 Gone"},
	"GET /api/analytics/user-agents":               {ui: true, mcp: true, mcpName: "spm_user_agents", untrusted: true},
	"GET /api/audit-log":                           {ui: true},
	"GET /api/auth/oidc":                           {ui: true},
	"GET /api/auth/oidc/callback":                  {apiOnly: "the identity provider sends the browser back to it"},
	"GET /api/auth/oidc/login":                     {ui: true},
	"GET /api/blacklists/enforcement":              {ui: true},
	"GET /api/cache/statistics":                    {ui: true},
	"GET /api/client-groups":                       {ui: true},
	"GET /api/client-groups/{id}":                  {notInUI: "the Clients page reads every group at once (GET /api/client-groups); one group by id is for scripts"},
	"GET /api/client-setup":                        {ui: true},
	"GET /api/client-setup/ca.crt":                 {apiOnly: "a device fetches it while it is set up"},
	"GET /api/clients/statistics":                  {ui: true},
	"GET /api/clients/{ip}/details":                {ui: true},
	"GET /api/clients/{ip}/{prefix}/details":       {notInUI: "the same detail as GET /api/clients/{ip}/details for a CIDR written with its slash unencoded; the dashboard encodes it"},
	"GET /api/config/snapshots":                    {ui: true, cli: true},
	"GET /api/config/snapshots/{id}/diff":          {ui: true, cli: true},
	"GET /api/dashboard/summary":                   {ui: true, mcp: true, mcpName: "spm_dashboard", untrusted: true},
	"GET /api/database/export":                     {ui: true},
	"GET /api/database/size":                       {ui: true},
	"GET /api/database/stats":                      {notInUI: "row counts per table are a maintenance query, not something the dashboard acts on"},
	"GET /api/docs":                                {apiOnly: "the API describing itself to its clients"},
	"GET /api/domain-blacklist":                    {ui: true, cli: true, mcp: true, mcpName: "spm_list_domain_blocklist", untrusted: true},
	"GET /api/domain-blacklist/export":             {ui: true, cli: true},
	"GET /api/domain-blacklist/presets":            {ui: true},
	"GET /api/domain-blacklist/sources":            {ui: true, cli: true},
	"GET /api/domain-whitelist":                    {ui: true, cli: true},
	"GET /api/domain-whitelist/export":             {ui: true, cli: true},
	"GET /api/domain-whitelist/presets":            {ui: true},
	"GET /api/domain-whitelist/sources":            {ui: true, cli: true},
	"GET /api/domains/statistics":                  {apiOnly: "retired: it answers 410 Gone"},
	"GET /api/egress-allowlist":                    {ui: true, cli: true},
	"GET /api/egress-providers":                    {ui: true},
	"GET /api/health":                              {ui: true},
	"GET /api/ip-blacklist":                        {ui: true, cli: true},
	"GET /api/ip-blacklist/export":                 {ui: true, cli: true},
	"GET /api/ip-blacklist/sources":                {ui: true, cli: true},
	"GET /api/ip-whitelist":                        {ui: true, cli: true},
	"GET /api/ip-whitelist/export":                 {ui: true, cli: true},
	"GET /api/ip-whitelist/sources":                {ui: true, cli: true},
	"GET /api/logs":                                {ui: true, cli: true, mcp: true, mcpName: "spm_recent_logs", untrusted: true},
	"GET /api/logs/export":                         {ui: true},
	"GET /api/logs/stats":                          {ui: true},
	"GET /api/logs/timeline":                       {ui: true},
	"GET /api/maintenance/backup-config":           {ui: true},
	"GET /api/maintenance/check-cert-security":     {ui: true},
	"GET /api/notifications/status":                {ui: true},
	"GET /api/openapi.json":                        {apiOnly: "the API describing itself to its clients"},
	"GET /api/ready":                               {apiOnly: "a probe for the container runtime or a load balancer, not an action"},
	"GET /api/security/cve":                        {ui: true},
	"GET /api/security/download-ca":                {ui: true},
	"GET /api/security/rate-limits":                {ui: true, cli: true},
	"GET /api/security/score":                      {apiOnly: "retired: it answers 410 Gone"},
	"GET /api/session":                             {ui: true},
	"GET /api/settings":                            {ui: true, cli: true},
	"GET /api/status":                              {ui: true, cli: true, mcp: true, mcpName: "spm_status"},
	"GET /api/tokens":                              {ui: true},
	"GET /api/traffic/statistics":                  {apiOnly: "retired: it answers 410 Gone"},
	"GET /api/waf/categories":                      {ui: true, mcp: true, mcpName: "spm_waf_categories"},
	"GET /api/waf/events/{id}":                     {ui: true},
	"GET /api/waf/heuristics":                      {ui: true},
	"GET /api/waf/policy":                          {ui: true},
	"GET /api/waf/stats":                           {ui: true},
	"GET /api/waf/status":                          {ui: true},
	"GET /api/waf/trajectories":                    {ui: true},
	"GET /api/waf/trajectories/{id}":               {ui: true},
	"GET /api/ws-token":                            {ui: true},
	"GET /api/ws/logs":                             {ui: true},
	"GET /health":                                  {apiOnly: "a probe for the container runtime or a load balancer, not an action"},
	"GET /livez":                                   {apiOnly: "a probe for the container runtime or a load balancer, not an action"},
	"GET /metrics":                                 {apiOnly: "Prometheus scrapes it"},
	"GET /readyz":                                  {apiOnly: "a probe for the container runtime or a load balancer, not an action"},
	"POST /api/auth/login":                         {ui: true},
	"POST /api/auth/refresh":                       {apiOnly: "a client signed in with the password renews its token here; the UI signs in with a cookie, the command and the MCP server with an API token"},
	"POST /api/blacklists/import":                  {ui: true, cli: true},
	"POST /api/blacklists/import-geo":              {ui: true},
	"POST /api/change-password":                    {ui: true},
	"POST /api/client-groups":                      {ui: true},
	"POST /api/config/snapshots":                   {ui: true, cli: true},
	"POST /api/config/snapshots/{id}/restore":      {ui: true, cli: true},
	"POST /api/counters/reset":                     {ui: true},
	"POST /api/database/optimize":                  {ui: true},
	"POST /api/database/reset":                     {notInUI: "deletes every list, setting and log at once; the dashboard restores a backup or a snapshot instead"},
	"POST /api/dns/detect":                         {ui: true},
	"POST /api/domain-blacklist":                   {ui: true, cli: true, mcp: true, mcpName: "spm_block_domain"},
	"POST /api/domain-blacklist/bulk-delete":       {ui: true},
	"POST /api/domain-blacklist/import":            {apiOnly: "retired: it answers 410 Gone"},
	"POST /api/domain-blacklist/presets/{preset}":  {ui: true},
	"POST /api/domain-whitelist":                   {ui: true, cli: true},
	"POST /api/domain-whitelist/bulk-delete":       {ui: true},
	"POST /api/domain-whitelist/import":            {ui: true, cli: true},
	"POST /api/domain-whitelist/presets/{preset}":  {ui: true},
	"POST /api/egress-allowlist":                   {ui: true, cli: true, mcp: true, mcpName: "spm_allow_egress"},
	"POST /api/egress-allowlist/bulk-delete":       {ui: true},
	"POST /api/egress-providers/url":               {ui: true},
	"POST /api/egress-providers/{name}/apply-held": {ui: true},
	"POST /api/egress-providers/{name}/refresh":    {ui: true},
	"POST /api/internal/alert":                     {apiOnly: "the WAF calls it, nobody else"},
	"POST /api/internal/signals":                   {apiOnly: "the WAF calls it, nobody else"},
	"POST /api/ip-blacklist":                       {ui: true, cli: true},
	"POST /api/ip-blacklist/bulk-delete":           {ui: true},
	"POST /api/ip-blacklist/import":                {apiOnly: "retired: it answers 410 Gone"},
	"POST /api/ip-whitelist":                       {ui: true, cli: true},
	"POST /api/ip-whitelist/bulk-delete":           {ui: true},
	"POST /api/ip-whitelist/import":                {ui: true, cli: true},
	"POST /api/log-forward/test":                   {ui: true},
	"POST /api/logout":                             {ui: true},
	"POST /api/logs/clear":                         {ui: true},
	"POST /api/logs/clear-old":                     {ui: true},
	"POST /api/maintenance/clear-cache":            {ui: true},
	"POST /api/maintenance/reload-config":          {ui: true, mcp: true, mcpName: "spm_reload_config"},
	"POST /api/maintenance/reload-dns":             {ui: true},
	"POST /api/maintenance/restore-config":         {ui: true},
	"POST /api/notifications/test":                 {ui: true},
	"POST /api/settings":                           {ui: true},
	"POST /api/tokens":                             {ui: true},
	"POST /api/waf/categories/toggle":              {mcp: true, mcpName: "spm_toggle_waf_category", notInUI: "the dashboard changes WAF categories through the WAF policy, which keeps one history (PUT /api/waf/policy)"},
	"POST /api/waf/policy/exceptions":              {ui: true},
	"POST /api/waf/policy/observe-rules":           {ui: true},
	"POST /api/waf/test-rule":                      {ui: true},
	"PUT /api/client-groups/{id}":                  {ui: true},
	"PUT /api/domain-blacklist/sources/{id}/scope": {ui: true},
	"PUT /api/egress-providers/{name}":             {ui: true},
	"PUT /api/ip-blacklist/sources/{id}/scope":     {ui: true},
	"PUT /api/settings/{name}":                     {cli: true, notInUI: "the dashboard saves a section of settings at once (POST /api/settings), which validates them together"},
	"PUT /api/waf/policy":                          {ui: true},
}
