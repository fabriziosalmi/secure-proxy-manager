package database

// HostKey returns the SQL expression that reduces the destination in column
// col to its host, in three steps:
//
//   - after the scheme: "http://host/login" -> "host/login" (no "://", as
//     in "host:443", leaves it as it is);
//   - before the path: "host/login" -> "host";
//   - without a default port: a trailing :443 or :80 is dropped; any other
//     port stays, because it is another service. LIKE ':443' needs the colon,
//     so "host:8443" keeps its port.
//
// The analytics top lists group by it, and the start-up reconstruction of
// sinkholed requests (reconstruct.go) matches it against the blacklist, so
// both read the same host from the same row. col is a column name written by
// the caller, never a value (SQLText).
func HostKey(col SQLText) SQLText {
	scheme := "instr(" + col + ", '://')"
	// substr from 1 when there is no scheme, from just after "://" otherwise.
	rest := "substr(" + col + ", 1 + (" + scheme + " + 2) * (" + scheme + " > 0))"
	// Appending "/" makes instr find one in a bare host too.
	hostPort := "substr(" + rest + ", 1, instr(" + rest + " || '/', '/') - 1)"
	return `CASE
	WHEN ` + hostPort + ` LIKE '%:443' THEN substr(` + hostPort + `, 1, length(` + hostPort + `) - 4)
	WHEN ` + hostPort + ` LIKE '%:80' THEN substr(` + hostPort + `, 1, length(` + hostPort + `) - 3)
	ELSE ` + hostPort + ` END`
}
