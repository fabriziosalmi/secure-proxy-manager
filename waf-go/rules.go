package main

import "regexp"

// ── Rule engine types ───────────────────────────────────────────────────────

// Rule represents a single WAF detection pattern with metadata.
type Rule struct {
	ID       string         // Unique identifier, e.g. "SQLi-001"
	Pattern  *regexp.Regexp // Precompiled RE2 pattern
	Severity int            // Score contribution: 10=critical, 7=high, 4=medium, 2=low
	Tier     int            // Execution order: 1=fast, 2=moderate, 3=expensive
}

// CategoryRules groups rules by attack category.
type CategoryRules struct {
	Category string
	Rules    []Rule
}

// MatchResult captures what triggered a block.
type MatchResult struct {
	Category string
	RuleID   string
	Pattern  string
	Score    int
}

func r(id string, pattern string, severity, tier int) Rule {
	return Rule{ID: id, Pattern: regexp.MustCompile(pattern), Severity: severity, Tier: tier}
}

// ── Rule definitions ────────────────────────────────────────────────────────

var blockRules = []CategoryRules{
	// ── SQL INJECTION ────────────────────────────────────────────────────
	{
		Category: "SQL_INJECTION",
		Rules: []Rule{
			// Tier 1 — fast keyword patterns
			r("SQLi-001", `(?i)(UNION\s+(ALL\s+)?SELECT)`, 10, 1),
			r("SQLi-002", `(?i)(DROP\s+(TABLE|DATABASE|INDEX|VIEW))`, 10, 1),
			r("SQLi-003", `(?i)(INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|TRUNCATE\s+TABLE)`, 7, 1),
			r("SQLi-004", `(?i)(;\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER|TRUNCATE|EXEC))`, 10, 1),

			// Tier 2 — compound patterns
			r("SQLi-005", `(?i)(WAITFOR\s+DELAY|BENCHMARK\s*\(|SLEEP\s*\(|pg_sleep\s*\()`, 10, 2),
			r("SQLi-006", `(?i)(\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+|\b1\s*=\s*1\b)`, 7, 2),
			r("SQLi-007", `(?i)(xp_cmdshell|sp_executesql|sp_configure|xp_regread)`, 10, 2),
			r("SQLi-008", `(?i)(LOAD_FILE\s*\(|INTO\s+(OUT|DUMP)FILE)`, 10, 2),
			r("SQLi-009", `(?i)(INFORMATION_SCHEMA|TABLE_SCHEMA|COLUMN_NAME|sys\.objects|mysql\.user)`, 10, 2),
			r("SQLi-010", `(?i)ORDER\s+BY\s+[0-9]{1,2}\b`, 4, 2),           // SQLi column enumeration
			r("SQLi-011", `(?i)GROUP\s+BY\s+.*HAVING\s+1\s*=\s*1`, 7, 2),   // SQLi bypass
			r("SQLi-012", `(?i)SELECT\s+.*INTO\s+OUTFILE`, 10, 2),           // DB dump to file
			r("SQLi-013", `(?i)db\.\w+\.find\(\{`, 7, 2),                    // NoSQL injection (MongoDB)

			// Tier 3 — evasion-hardened
			r("SQLi-014", `(?i)(0x[0-9a-f]{6,}|UNHEX\s*\(|CHAR\s*\(|CAST\s*\(|CONVERT\s*\()`, 4, 3),
			r("SQLi-015", `(?i)(%27|%23|%2d%2d)`, 4, 3),
			r("SQLi-016", `/\*.*\*/`, 2, 3),
		},
	},

	// ── XSS ATTACKS ─────────────────────────────────────────────────────
	{
		Category: "XSS_ATTACKS",
		Rules: []Rule{
			// Tier 1
			r("XSS-001", `(?i)<script[\s>]`, 10, 1),
			r("XSS-002", `(?i)(javascript\s*:|vbscript\s*:|data\s*:\s*text/html)`, 10, 1),

			// Tier 2
			r("XSS-003", `(?i)\bon(load|error|click|focus|blur|mouseover|mouseout|submit|reset|change|keydown|keyup|keypress|dblclick|contextmenu|drag(start|end|over)?|drop|paste|copy|cut|input)\s*=`, 10, 2),
			r("XSS-004", `(?i)(<iframe|<embed|<object|<applet|<form\s)`, 10, 2),
			r("XSS-005", `(?i)(<svg|<math|<animate|<set\s|<image\s)`, 10, 2),
			r("XSS-006", `(?i)(document\.(cookie|domain|write|location)|window\.(location|open)|eval\s*\(|Function\s*\()`, 10, 2),
			r("XSS-007", `(?i)(setTimeout|setInterval|execScript|msSetImmediate)\s*\(`, 4, 2),

			// Tier 3
			r("XSS-008", `(?i)(fromCharCode|String\.fromCharCode|atob\s*\(|btoa\s*\()`, 4, 3),
			r("XSS-009", `(\{\{.*\}\}|\$\{[^}]+\}|<%-.*%>)`, 4, 3),
			r("XSS-010", `(?i)(expression\s*\(|url\s*\(|@import)`, 4, 3),
		},
	},

	// ── COMMAND INJECTION ───────────────────────────────────────────────
	{
		Category: "COMMAND_INJECTION",
		Rules: []Rule{
			// Tier 1
			r("CMDi-001", `;\s*(ls|cat|id|whoami|uname|wget|curl|nc|ncat|bash|sh|dash|zsh|python|perl|ruby|php|node)\b`, 10, 1),
			r("CMDi-002", `\|\s*(cat|grep|sed|awk|cut|tr|base64|xxd|nc|bash|sh)\b`, 10, 1),

			// Tier 2
			r("CMDi-003", `\$\([^)]+\)`, 7, 2),
			r("CMDi-004", "`.+`", 7, 2),
			r("CMDi-005", `(?i)(;\s*rm\s+-rf|;\s*chmod\s+[0-7]{3,4}|;\s*chown\s+|;\s*mkfifo\s+)`, 10, 2),
			r("CMDi-006", `(?i)(cmd\s*/c|powershell\s+.*-[eE]|Start-Process|Invoke-Expression)`, 10, 2),

			// Tier 3
			r("CMDi-007", `(?i)(__import__\s*\(|subprocess\.|os\.(system|popen|exec)|exec\s*\()`, 7, 3),
			r("CMDi-008", `(?i)(\bsystem\s*\(|\bpassthru\s*\(|\bshell_exec\s*\(|\bproc_open\s*\()`, 7, 3),
		},
	},

	// ── DIRECTORY TRAVERSAL ─────────────────────────────────────────────
	{
		Category: "DIRECTORY_TRAVERSAL",
		Rules: []Rule{
			// Tier 1
			r("DirT-001", `(\.\./){2,}`, 10, 1),
			r("DirT-002", `(\.\.\\){2,}`, 10, 1),

			// Tier 2
			r("DirT-003", `(?i)/etc/(passwd|shadow|group|sudoers|hosts|crontab)`, 10, 2),
			r("DirT-004", `(?i)/(root|home/\w+)/\.(ssh|bash_history|bashrc|profile)`, 7, 2),
			r("DirT-005", `(?i)(windows[\\/]system32|windows[\\/]win\.ini|boot\.ini)`, 10, 2),
			r("DirT-006", `(?i)(\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9._$-]+)`, 4, 2),

			// Tier 3
			r("DirT-007", `(?i)(%2e%2e|%252e%252e|%c0%ae|%c0%af|%c0%2f|%c0%5c|%c1%1c|%c1%9c|%c1%af|%e0%80%af)`, 10, 3),
			r("DirT-008", `(%00|\\x00)`, 10, 3),
			r("DirT-009", `(?i)/proc/(self|version|cpuinfo|meminfo|net/)`, 10, 3),
		},
	},

	// ── DATA LEAK PREVENTION ────────────────────────────────────────────
	{
		Category: "DATA_LEAK_PREVENTION",
		Rules: []Rule{
			// Tier 2
			r("DLP-001", `(?i)(password|passwd|pwd|secret|api_key|apikey|access_token|auth_token)\s*=\s*[^\s&]{3,}`, 4, 2),
			r("DLP-002", `AKIA[0-9A-Z]{16}`, 10, 2),
			r("DLP-003", `ghp_[A-Za-z0-9_]{20,}`, 10, 2),
			r("DLP-004", `xox[bpras]-[0-9]{10,13}-`, 10, 2),
			r("DLP-005", `-----BEGIN (RSA |EC |DSA )?PRIVATE KEY`, 10, 2),

			// Tier 3
			r("DLP-006", `\b\d{3}-\d{2}-\d{4}\b`, 2, 3),
			r("DLP-007", `(?i)(mongodb(\+srv)?://|postgres(ql)?://|mysql://|redis://)(\S+:)?\S+@`, 7, 3),
		},
	},

	// ── SSRF ────────────────────────────────────────────────────────────
	{
		Category: "SSRF",
		Rules: []Rule{
			// Tier 1
			r("SSRF-001", `(?i)(169\.254\.169\.254|metadata\.google\.internal)`, 10, 1),

			// Tier 2
			r("SSRF-002", `(?i)(http|https)://(127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+)`, 10, 2),
			r("SSRF-003", `(?i)(http|https)://(172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)`, 10, 2),
			r("SSRF-004", `(?i)/latest/(meta-data|user-data|dynamic|api/token)`, 10, 2),
			r("SSRF-005", `(?i)(file|gopher|dict|ftp)://`, 10, 2),

			// Tier 3
			r("SSRF-006", `(?i)(amazonaws\.com|compute\.googleapis\.com|management\.azure\.com)`, 4, 3),
			r("SSRF-007", `:(22|3306|5432|6379|11211|27017|9200|2375|2376)\b`, 4, 3),
		},
	},

	// ── LOG4SHELL / JNDI ────────────────────────────────────────────────
	{
		Category: "LOG4SHELL",
		Rules: []Rule{
			// Tier 1
			r("L4S-001", `(?i)\$\{[^}]*jndi\s*:`, 10, 1),

			// Tier 2
			r("L4S-002", `(?i)\$\{(lower|upper|env|sys|java|base64)[^}]*\}`, 7, 2),
			r("L4S-003", `(?i)(ldap|rmi|ldaps|dns|iiop|corba|nds)://`, 7, 2),

			// Tier 3
			r("L4S-004", `(?i)(\$\{.*){3,}`, 4, 3),
			r("L4S-005", `(?i)(ObjectInputStream|readObject|Runtime\.getRuntime|ProcessBuilder)`, 7, 3),
		},
	},

	// ── XXE ─────────────────────────────────────────────────────────────
	{
		Category: "XXE",
		Rules: []Rule{
			// Tier 1
			r("XXE-001", `(?i)<!ENTITY\s+\S+\s+SYSTEM`, 10, 1),
			r("XXE-002", `(?i)<!DOCTYPE\s+\S+\s+\[`, 7, 1),

			// Tier 2
			r("XXE-003", `(?i)(file|php|expect|data|java|jar|netdoc)://`, 7, 2),
			r("XXE-004", `(?i)%\w+;`, 4, 2),

			// Tier 3
			r("XXE-005", `(?i)(<!ENTITY\s+\S+\s+["'][^"']*["']\s*>.*){3,}`, 7, 3),
			r("XXE-006", `(?i)(CDATA\s*\[|PUBLIC\s+["'][^"']*["'])`, 4, 3),
		},
	},

	// ── PROTOTYPE POLLUTION ─────────────────────────────────────────────
	{
		Category: "PROTOTYPE_POLLUTION",
		Rules: []Rule{
			r("PP-001", `(__proto__|constructor\.prototype)`, 10, 2),
			r("PP-002", `\[["'](constructor|__proto__|prototype)["']\]\s*=`, 10, 2),
			r("PP-003", `(?i)(Object\.(assign|create|defineProperty|setPrototypeOf))`, 4, 3),
			r("PP-004", `(?i)(\["__proto__"\]|\['__proto__'\])`, 7, 3),
		},
	},

	// ── PATH MANIPULATION / FILE INCLUSION ───────────────────────────────
	{
		Category: "PATH_MANIPULATION",
		Rules: []Rule{
			r("PATH-001", `(?i)(php://filter|php://input|php://expect|php://fd)`, 10, 2),
			r("PATH-002", `(?i)(phar://|zip://|rar://|compress\.(zlib|bzip2)://)`, 10, 2),
			r("PATH-003", `(?i)(include|require|include_once|require_once)\s*\(`, 4, 3),
			r("PATH-004", `(?i)/var/(log|www)/.*\.(log|php|conf)`, 4, 3),
			r("PATH-005", `(?i)(convert\.iconv|convert\.base64)`, 4, 3),
		},
	},

	// ── UNICODE HOMOGRAPH OBFUSCATION ───────────────────────────────────
	{
		Category: "UNICODE_OBFUSCATION",
		Rules: []Rule{
			r("UNI-001", "(\xe2\x80\x8b|\xe2\x80\x8c|\xe2\x80\x8d)", 10, 1),
			r("UNI-002", "(\xe2\x80\xae|\xe2\x80\xad)", 10, 1),
			r("UNI-003", "(?i)[a-z]+[\xd0\xb0\xd0\xb5\xd0\xbe\xd1\x80\xd1\x81\xd1\x83\xd1\x96\xd1\x98]+[a-z]+", 7, 2),
			r("UNI-004", "(?i)[\xd0\xb0\xd0\xb5\xd0\xbe\xd1\x80\xd1\x81\xd1\x83\xd1\x96\xd1\x98]+[a-z]+", 4, 2),
			r("UNI-005", "(?i)[a-z]+[\xce\xbf\xce\xbd\xcf\x81\xcf\x84]+[a-z]+", 4, 2),
		},
	},

	// ── CLOUD & SaaS API KEYS (egress leak prevention) ──────────────────
	{
		Category: "CLOUD_SECRETS",
		Rules: []Rule{
			// Tier 1 — high-entropy fixed-prefix tokens (fast, precise)
			r("CLOUD-001", `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`, 10, 1),
			r("CLOUD-002", `AIza[0-9A-Za-z\-_]{35}`, 10, 1),

			// Tier 2 — SaaS tokens
			r("CLOUD-003", `sk-[a-zA-Z0-9]{20,}`, 10, 2),               // OpenAI
			r("CLOUD-004", `sk_live_[0-9a-zA-Z]{24,}`, 10, 2),          // Stripe live
			r("CLOUD-005", `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`, 10, 2), // SendGrid
			r("CLOUD-006", `SK[0-9a-fA-F]{32}`, 7, 2),                  // Twilio
			r("CLOUD-007", `AC[a-f0-9]{32}`, 7, 2),                     // Twilio Account SID
			r("CLOUD-008", `gho_[a-zA-Z0-9]{36}`, 10, 2),              // GitHub OAuth
			r("CLOUD-009", `sq0atp-[0-9A-Za-z\-_]{22}`, 10, 2),        // Square
			r("CLOUD-010", `key-[0-9a-fA-F]{32}`, 7, 2),               // Mailgun
			r("CLOUD-011", `[0-9a-fA-F]{32}-us[0-9]{1,2}`, 7, 2),      // Mailchimp

			// Tier 3 — patterns needing more context
			r("CLOUD-012", `(?i)vault:v[0-9]:[a-zA-Z0-9+/=]+`, 10, 3), // HashiCorp Vault
			r("CLOUD-013", `(?i)x-amz-security-token:\s*[a-zA-Z0-9+/=]{100,}`, 10, 3), // AWS STS
			r("CLOUD-014", `EAACEdEose0cBA[0-9A-Za-z]+`, 7, 3),        // Facebook Graph
			r("CLOUD-015", `(?i)amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, 10, 3), // Amazon MWS
		},
	},

	// ── SENSITIVE FILES (data exfiltration via URL path) ─────────────────
	{
		Category: "SENSITIVE_FILES",
		Rules: []Rule{
			// Tier 1
			r("FILE-001", `(?i)\.git/(config|index|HEAD|objects|refs)`, 10, 1),
			r("FILE-002", `(?i)(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\b|$)`, 10, 1),

			// Tier 2
			r("FILE-003", `(?i)(\.env|\.env\.bak|\.env\.old|\.env\.local)(\b|$)`, 10, 2),
			r("FILE-004", `(?i)(wp-config\.php|config\.php\.bak|settings\.py|web\.config)`, 10, 2),
			r("FILE-005", `(?i)\.(sql|sql\.gz|sql\.zip|sql\.bak)(\b|$)`, 7, 2),
			r("FILE-006", `(?i)\.(pfx|p12|pem|key|ovpn)(\b|$)`, 7, 2),
			r("FILE-007", `(?i)\.docker/config\.json`, 10, 2),
			r("FILE-008", `(?i)\.aws/(credentials|config)`, 10, 2),
			r("FILE-009", `(?i)\.(bash_history|zsh_history|mysql_history|psql_history)`, 7, 2),
			r("FILE-010", `(?i)htpasswd`, 7, 2),
			r("FILE-011", `(?i)\.ssh/(authorized_keys|known_hosts)`, 7, 2),
			r("FILE-012", `(?i)/var/run/secrets/kubernetes\.io`, 10, 2),

			// Tier 3
			r("FILE-013", `(?i)\.(tfstate|tfvars)(\b|$)`, 10, 3),      // Terraform
			r("FILE-014", `(?i)(kubeconfig|\.kube/config)`, 10, 3),
			r("FILE-015", `(?i)backup_[0-9]{4}-[0-9]{2}-[0-9]{2}\.(tar|zip|gz)`, 4, 3),
		},
	},

	// ── WEB SHELLS & C2 INDICATORS ──────────────────────────────────────
	{
		Category: "WEBSHELL_C2",
		Rules: []Rule{
			// Tier 1
			r("SHELL-001", `(?i)/(r57|c99|c100|b374k|wso|alfa|mini|leaf)\.php`, 10, 1),

			// Tier 2
			r("SHELL-002", `(?i)cmd=(system|exec|passthru|shell_exec|popen)`, 10, 2),
			r("SHELL-003", `(?i)(eval|base64_decode|gzuncompress|gzinflate|str_rot13)\s*\(`, 7, 2),
			r("SHELL-004", `(?i)\b(whoami|ifconfig|ipconfig|systeminfo)\b`, 10, 2),
			r("SHELL-005", `(?i)(wget|curl)\s+https?://.*\s+-[oO]`, 10, 2),
			r("SHELL-006", `(?i)(python|bash|perl|ruby|php)\s+-[ice]\s`, 10, 2),
			r("SHELL-007", `(?i)nc\s+-[lnvep]+\s`, 10, 2),
			r("SHELL-008", `(?i)(powershell\.exe|cmd\.exe)\s`, 7, 2),
			r("SHELL-009", `(?i)(mimikatz|CobaltStrike|Metasploit|Beacon)`, 10, 2),

			// Tier 3
			r("SHELL-010", `(?i)(IEX|Invoke-Expression|Invoke-WebRequest|iwr)\s`, 7, 3),
			r("SHELL-011", `(?i)powershell\s+-ExecutionPolicy\s+Bypass`, 10, 2),
			r("SHELL-012", `(?i)viewstate=[A-Za-z0-9+/=]{50,}`, 4, 3),
		},
	},

	// ── CRYPTO MINING & TUNNELING ───────────────────────────────────────
	{
		Category: "CRYPTO_TUNNEL",
		Rules: []Rule{
			// Tier 1
			r("MINE-001", `(?i)stratum(\+| )tcp://`, 10, 1),

			// Tier 2
			r("MINE-002", `(?i)(monerohash|nanopool|ethermine|miningpoolhub|f2pool|nicehash)`, 10, 2),
			r("MINE-003", `(?i)(xmrig|cpuminer|minerd|cgminer|bfgminer)`, 10, 2),
			r("MINE-004", `(?i)\.onion(/|$)`, 7, 2),
			r("MINE-005", `(?i)(ngrok\.com|localtunnel\.me|serveo\.net|bore\.pub)`, 7, 2),
			r("MINE-006", `(?i)(anydesk\.com|teamviewer\.com|logmein\.com).*(/download|/api)`, 4, 2),

			// Tier 3
			r("MINE-007", `(?i)(iodine|dnscat2|chisel|rathole)`, 7, 3),
			r("MINE-008", `(?i)application/dns-message`, 7, 3),  // DNS over HTTPS tunneling
		},
	},

	// ── DATA EXFILTRATION (pastebins & file sharing) ────────────────────
	{
		Category: "DATA_EXFIL",
		Rules: []Rule{
			// Tier 2
			r("EXFIL-001", `(?i)pastebin\.com/raw/`, 7, 2),
			r("EXFIL-002", `(?i)gist\.githubusercontent\.com`, 4, 2),
			r("EXFIL-003", `(?i)discord\.com/api/webhooks/`, 10, 2),
			r("EXFIL-004", `(?i)api\.telegram\.org/bot`, 7, 2),
			r("EXFIL-005", `(?i)(transfer\.sh|file\.io|0x0\.st)/`, 7, 2),
			r("EXFIL-006", `(?i)mega\.nz/(#!|file/)`, 4, 2),

			// Tier 3
			r("EXFIL-007", `(?i)hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/`, 10, 3),
			r("EXFIL-008", `(?i)https://[a-zA-Z0-9-]+\.firebaseio\.com`, 4, 3),
		},
	},

	// ── POST-EXPLOITATION & LATERAL MOVEMENT ────────────────────────────
	{
		Category: "POST_EXPLOIT",
		Rules: []Rule{
			// Tier 2
			r("PEXP-001", `(?i)base64\s+-d\s*\|.*sh\b`, 10, 2),
			r("PEXP-002", `S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+`, 7, 2), // Windows SID
			r("PEXP-003", `(?i)net\s+(user|group|localgroup)\s+/domain`, 10, 2),
			r("PEXP-004", `(?i)kerberos\.keytab`, 10, 2),

			// Tier 3
			r("PEXP-005", `(?i)(ansible_ssh_pass|ansible_become_pass)`, 10, 3),
			r("PEXP-006", `(?i)\[profile\s+[a-zA-Z0-9_-]+\]`, 4, 3), // AWS CLI config
			r("PEXP-007", `(?i)kind:\s*Secret`, 7, 3), // K8s Secret manifest
		},
	},

	// ── JAVA DESERIALIZATION & FRAMEWORK EXPLOITS ────────────────────────
	{
		Category: "JAVA_DESER",
		Rules: []Rule{
			// Tier 2
			r("JAVA-001", `(?i)T\(java\.lang\.Runtime\)\.getRuntime\(\)\.exec\(`, 10, 2), // SpEL
			r("JAVA-002", `(?i)apache\.commons\.collections`, 7, 2),
			r("JAVA-003", `(?i)javax\.faces\.ViewState`, 4, 2),

			// Tier 3
			r("JAVA-004", `(?i)(ysoserial|CommonsCollections|JRMPClient)`, 10, 3),
		},
	},

	// ── PROTOCOL ANOMALY (suspicious headers/methods in egress) ─────────
	{
		Category: "PROTOCOL_ANOMALY",
		Rules: []Rule{
			// Tier 2 — inspect via header string
			r("PROTO-001", `(?i)User-Agent:\s*$`, 4, 2),                    // Empty UA
			r("PROTO-002", `(?i)(X-Scanner|X-Scan):\s*(Netsparker|Acunetix|Sqlmap)`, 10, 2),
			r("PROTO-003", `(?i)Expect:\s*100-continue`, 2, 2),             // HTTP smuggling
			r("PROTO-004", `(?i)X-Forwarded-For:.*,.*,.*,`, 4, 2),         // Proxy chain

			// Tier 3
			r("PROTO-005", `(?i)(?:%[0-9a-fA-F]{2}){15,}`, 4, 3),         // Massive URL encoding
			r("PROTO-006", `(?i)[a-zA-Z0-9+/]{200,}=?=?`, 4, 3),          // Large base64 blob
		},
	},

	// ── FINANCIAL DATA (compliance) ─────────────────────────────────────
	{
		Category: "FINANCIAL_DATA",
		Rules: []Rule{
			// Tier 3 — low severity, scored but rarely blocks alone
			r("FIN-001", `\b4[0-9]{12}(?:[0-9]{3})?\b`, 2, 3),            // Visa
			r("FIN-002", `\b5[1-5][0-9]{14}\b`, 2, 3),                     // MasterCard
			r("FIN-003", `\b3[47][0-9]{13}\b`, 2, 3),                      // Amex
			r("FIN-004", `\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b`, 2, 3),    // IBAN
			r("FIN-005", `\bbc1[qp][a-z0-9]{38,58}\b`, 4, 3),             // Bitcoin SegWit
			r("FIN-006", `\b0x[a-fA-F0-9]{40}\b`, 4, 3),                   // Ethereum address
		},
	},

	// ── RANSOMWARE INDICATORS ───────────────────────────────────────────
	{
		Category: "RANSOMWARE",
		Rules: []Rule{
			r("RANSOM-001", `(?i)\.(crypt|locked|crypted|encrypted|cerber|locky|wcry)$`, 10, 2),
			r("RANSOM-002", `(?i)DECRYPT_INSTRUCTION`, 10, 2),
			r("RANSOM-003", `(?i)(bitcoincash:[qzp][a-z0-9]{41}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})`, 4, 3),
		},
	},
}

// Response-specific rules (applied in RESPMOD to outbound responses)
var respRules = []CategoryRules{
	{
		Category: "RESPONSE_XSS",
		Rules: []Rule{
			r("RESP-001", `(?i)<script>alert\(`, 10, 1),
			r("RESP-002", `(?i)document\.location\s*=\s*['"]https?://`, 7, 2),
			r("RESP-003", `(?i)document\.cookie`, 7, 2),
		},
	},
	{
		Category: "RESPONSE_SECRET_LEAK",
		Rules: []Rule{
			r("RESP-004", `-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY`, 10, 1),
			r("RESP-005", `(?i)(Password|Secret|API.?Key|Token)\s*[:=]\s*[^\s,]{8,}`, 4, 2),
		},
	},
}

// ── Rule matching engine ────────────────────────────────────────────────────

// matchRulesScored evaluates input against all rules in tiered order.
// Returns all matches and the total anomaly score.
func matchRulesScored(input string) ([]MatchResult, int) {
	var matches []MatchResult
	totalScore := 0
	matched := make(map[string]bool) // Deduplicate by rule ID

	// Prepare a compacted version (no whitespace) lazily — only used if
	// the normal input doesn't match, to catch evasion via space insertion.
	var compact string
	var compactReady bool

	for tier := 1; tier <= 3; tier++ {
		if totalScore >= blockThreshold && tier > 1 {
			break
		}

		for _, cr := range blockRules {
			for _, rule := range cr.Rules {
				if rule.Tier != tier {
					continue
				}
				if matched[rule.ID] {
					continue
				}
				hit := rule.Pattern.MatchString(input)
				if !hit {
					// Lazy-init compact on first miss
					if !compactReady {
						compact = compactInput(input)
						compactReady = true
					}
					hit = rule.Pattern.MatchString(compact)
				}
				if hit {
					matched[rule.ID] = true
					matches = append(matches, MatchResult{
						Category: cr.Category,
						RuleID:   rule.ID,
						Pattern:  rule.Pattern.String(),
						Score:    rule.Severity,
					})
					totalScore += rule.Severity
				}
			}
		}
	}

	return matches, totalScore
}
