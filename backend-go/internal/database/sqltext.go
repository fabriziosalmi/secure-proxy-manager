package database

import "strings"

// SQLText is a piece of SQL statement text: a column, a condition, a clause.
// A value from outside the program (a request, a row, a file) never belongs
// in it; it goes to the statement's arguments as a ? placeholder.
//
// An untyped string constant converts to SQLText by itself, so a constant
// fragment needs no conversion, while a string variable does not compile
// where SQLText is expected. sqltext_test.go allows an explicit SQLText(...)
// conversion only in Placeholders and JoinSQL, which build text from a count
// and from other SQLText. Helpers that put a parameter into the statement
// text take SQLText, so a caller cannot pass request input by mistake.
type SQLText string

// Placeholders is n comma-separated ? placeholders, for an IN (...) list.
func Placeholders(n int) SQLText {
	return SQLText(strings.TrimSuffix(strings.Repeat("?,", n), ","))
}

// JoinSQL joins fragments with sep, as strings.Join does.
func JoinSQL(parts []SQLText, sep SQLText) SQLText {
	s := make([]string, len(parts))
	for i, p := range parts {
		s[i] = string(p)
	}
	return SQLText(strings.Join(s, string(sep)))
}
