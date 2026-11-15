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
// An entry with nothing set is an operation only the API offers for now: a
// gap, not a decision. apiOnly is the decision that an operation belongs to
// the API alone, with the reason.
//
// The published document carries them as x-spm-surfaces and x-spm-api-only.

type surfaceSet struct {
	ui      bool
	cli     bool
	mcp     bool
	apiOnly string
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
	"DELETE /api/domain-blacklist/clear-all":       {ui: true},
	"DELETE /api/domain-blacklist/sources/{id}":    {ui: true},
	"DELETE /api/domain-blacklist/{id}":            {ui: true, mcp: true},
	"DELETE /api/domain-whitelist/sources/{id}":    {ui: true},
	"DELETE /api/domain-whitelist/{id}":            {ui: true},
	"DELETE /api/egress-allowlist/clear-all":       {},
	"DELETE /api/egress-allowlist/{id}":            {ui: true},
	"DELETE /api/egress-providers/url/{id}":        {ui: true},
	"DELETE /api/ip-blacklist/clear-all":           {ui: true},
	"DELETE /api/ip-blacklist/sources/{id}":        {ui: true},
	"DELETE /api/ip-blacklist/{id}":                {ui: true},
	"DELETE /api/ip-whitelist/sources/{id}":        {ui: true},
	"DELETE /api/ip-whitelist/{id}":                {ui: true},
	"DELETE /api/security/rate-limits/{ip}":        {},
	"DELETE /api/tokens/{id}":                      {ui: true},
	"GET /api/analytics/blocked-by-day":            {ui: true},
	"GET /api/analytics/cache-by-day":              {ui: true},
	"GET /api/analytics/coverage":                  {ui: true},
	"GET /api/analytics/file-extensions":           {ui: true},
	"GET /api/analytics/shadow-it":                 {ui: true, mcp: true},
	"GET /api/analytics/top-destinations":          {ui: true, mcp: true},
	"GET /api/analytics/top-domains":               {apiOnly: "retired: it answers 410 Gone"},
	"GET /api/analytics/user-agents":               {ui: true, mcp: true},
	"GET /api/audit-log":                           {ui: true},
	"GET /api/auth/oidc":                           {ui: true},
	"GET /api/auth/oidc/callback":                  {apiOnly: "the identity provider sends the browser back to it"},
	"GET /api/auth/oidc/login":                     {ui: true},
	"GET /api/blacklists/enforcement":              {ui: true},
	"GET /api/cache/statistics":                    {ui: true},
	"GET /api/client-groups":                       {ui: true},
	"GET /api/client-groups/{id}":                  {},
	"GET /api/client-setup":                        {ui: true},
	"GET /api/client-setup/ca.crt":                 {apiOnly: "a device fetches it while it is set up"},
	"GET /api/clients/statistics":                  {ui: true},
	"GET /api/clients/{ip}/details":                {ui: true},
	"GET /api/clients/{ip}/{prefix}/details":       {},
	"GET /api/config/snapshots":                    {ui: true},
	"GET /api/config/snapshots/{id}/diff":          {ui: true},
	"GET /api/dashboard/summary":                   {ui: true, mcp: true},
	"GET /api/database/export":                     {ui: true},
	"GET /api/database/size":                       {ui: true},
	"GET /api/database/stats":                      {},
	"GET /api/docs":                                {apiOnly: "the API describing itself to its clients"},
	"GET /api/domain-blacklist":                    {ui: true, mcp: true},
	"GET /api/domain-blacklist/export":             {ui: true},
	"GET /api/domain-blacklist/presets":            {ui: true},
	"GET /api/domain-blacklist/sources":            {ui: true},
	"GET /api/domain-whitelist":                    {ui: true},
	"GET /api/domain-whitelist/export":             {ui: true},
	"GET /api/domain-whitelist/presets":            {ui: true},
	"GET /api/domain-whitelist/sources":            {ui: true},
	"GET /api/domains/statistics":                  {apiOnly: "retired: it answers 410 Gone"},
	"GET /api/egress-allowlist":                    {ui: true},
	"GET /api/egress-providers":                    {ui: true},
	"GET /api/health":                              {ui: true},
	"GET /api/ip-blacklist":                        {ui: true},
	"GET /api/ip-blacklist/export":                 {ui: true},
	"GET /api/ip-blacklist/sources":                {ui: true},
	"GET /api/ip-whitelist":                        {ui: true},
	"GET /api/ip-whitelist/export":                 {ui: true},
	"GET /api/ip-whitelist/sources":                {ui: true},
	"GET /api/logs":                                {ui: true, mcp: true},
	"GET /api/logs/export":                         {ui: true},
	"GET /api/logs/stats":                          {ui: true},
	"GET /api/logs/timeline":                       {ui: true},
	"GET /api/maintenance/backup-config":           {ui: true},
	"GET /api/maintenance/check-cert-security":     {},
	"GET /api/notifications/status":                {ui: true},
	"GET /api/openapi.json":                        {apiOnly: "the API describing itself to its clients"},
	"GET /api/ready":                               {apiOnly: "a probe for the container runtime or a load balancer, not an action"},
	"GET /api/security/cve":                        {ui: true},
	"GET /api/security/download-ca":                {ui: true},
	"GET /api/security/rate-limits":                {},
	"GET /api/security/score":                      {apiOnly: "retired: it answers 410 Gone"},
	"GET /api/session":                             {ui: true},
	"GET /api/settings":                            {ui: true},
	"GET /api/status":                              {ui: true, mcp: true},
	"GET /api/tokens":                              {ui: true},
	"GET /api/traffic/statistics":                  {apiOnly: "retired: it answers 410 Gone"},
	"GET /api/waf/categories":                      {ui: true, mcp: true},
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
	"POST /api/blacklists/import":                  {ui: true},
	"POST /api/blacklists/import-geo":              {ui: true},
	"POST /api/change-password":                    {ui: true},
	"POST /api/client-groups":                      {ui: true},
	"POST /api/config/snapshots":                   {ui: true},
	"POST /api/config/snapshots/{id}/restore":      {ui: true},
	"POST /api/counters/reset":                     {ui: true},
	"POST /api/database/optimize":                  {ui: true},
	"POST /api/database/reset":                     {},
	"POST /api/dns/detect":                         {ui: true},
	"POST /api/domain-blacklist":                   {ui: true, mcp: true},
	"POST /api/domain-blacklist/bulk-delete":       {},
	"POST /api/domain-blacklist/import":            {ui: true},
	"POST /api/domain-blacklist/presets/{preset}":  {ui: true},
	"POST /api/domain-whitelist":                   {ui: true},
	"POST /api/domain-whitelist/import":            {ui: true},
	"POST /api/domain-whitelist/presets/{preset}":  {ui: true},
	"POST /api/egress-allowlist":                   {ui: true, mcp: true},
	"POST /api/egress-allowlist/bulk-delete":       {},
	"POST /api/egress-providers/url":               {ui: true},
	"POST /api/egress-providers/{name}/apply-held": {ui: true},
	"POST /api/egress-providers/{name}/refresh":    {ui: true},
	"POST /api/internal/alert":                     {apiOnly: "the WAF calls it, nobody else"},
	"POST /api/internal/signals":                   {apiOnly: "the WAF calls it, nobody else"},
	"POST /api/ip-blacklist":                       {ui: true},
	"POST /api/ip-blacklist/bulk-delete":           {},
	"POST /api/ip-blacklist/import":                {ui: true},
	"POST /api/ip-whitelist":                       {ui: true},
	"POST /api/ip-whitelist/import":                {ui: true},
	"POST /api/log-forward/test":                   {ui: true},
	"POST /api/logout":                             {ui: true},
	"POST /api/logs/clear":                         {ui: true},
	"POST /api/logs/clear-old":                     {},
	"POST /api/maintenance/clear-cache":            {ui: true},
	"POST /api/maintenance/reload-config":          {ui: true, mcp: true},
	"POST /api/maintenance/reload-dns":             {ui: true},
	"POST /api/maintenance/restore-config":         {ui: true},
	"POST /api/notifications/test":                 {ui: true},
	"POST /api/settings":                           {ui: true},
	"POST /api/tokens":                             {ui: true},
	"POST /api/waf/categories/toggle":              {mcp: true},
	"POST /api/waf/policy/exceptions":              {ui: true},
	"POST /api/waf/policy/observe-rules":           {ui: true},
	"POST /api/waf/test-rule":                      {ui: true},
	"PUT /api/client-groups/{id}":                  {ui: true},
	"PUT /api/domain-blacklist/sources/{id}/scope": {ui: true},
	"PUT /api/egress-providers/{name}":             {ui: true},
	"PUT /api/ip-blacklist/sources/{id}/scope":     {ui: true},
	"PUT /api/settings/{name}":                     {},
	"PUT /api/waf/policy":                          {ui: true},
}
