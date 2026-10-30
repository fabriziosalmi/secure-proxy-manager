package crs

// The rx operator on RE2, for WAF_REGEX_ENGINE=re2.
//
// coraza-wasilibs ships one, but it runs RE2 on the value as given, and RE2
// matches nothing on a byte that is not part of valid UTF-8, where Go's
// regexp (Coraza's own operator) reads U+FFFD, which ., \S and [^...] match.
// The value reaching an operator has been through the rule's
// transformations, so an attacker controls those bytes (t:urlDecodeUni turns
// %ff into one): a stray byte inside an attack would let it through. This
// operator gives RE2 the value as Go reads it (engine.AsRE2Input) and is
// otherwise Coraza's: (?sm) in front of the pattern, a pattern that matches
// arbitrary bytes on the binary matcher, the first nine captures when the
// transaction captures. Coraza's optional pre-filters (SecRxPreFilter) are
// left out. TestRXAgreesWithCorazas checks it against Go on the rule set's
// own patterns.

import (
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	re2 "github.com/wasilibs/go-re2"
	"rsc.io/binaryregexp"

	"secure-proxy-waf/internal/engine"
)

var rxCache sync.Map // pattern -> *re2.Regexp or *binaryregexp.Regexp

type rxRE2 struct{ re *re2.Regexp }

type rxBinary struct{ re *binaryregexp.Regexp }

func newRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := "(?sm)" + options.Arguments
	if matchesArbitraryBytes(data) {
		if v, ok := rxCache.Load("b:" + options.Arguments); ok {
			return &rxBinary{re: v.(*binaryregexp.Regexp)}, nil
		}
		re, err := binaryregexp.Compile(options.Arguments)
		if err != nil {
			return nil, err
		}
		rxCache.Store("b:"+options.Arguments, re)
		return &rxBinary{re: re}, nil
	}
	if v, ok := rxCache.Load(data); ok {
		return &rxRE2{re: v.(*re2.Regexp)}, nil
	}
	re, err := re2.Compile(data)
	if err != nil {
		return nil, err
	}
	rxCache.Store(data, re)
	return &rxRE2{re: re}, nil
}

func (o *rxRE2) Evaluate(tx plugintypes.TransactionState, value string) bool {
	value = engine.AsRE2Input(value)
	if !tx.Capturing() {
		return o.re.MatchString(value)
	}
	match := o.re.FindStringSubmatchIndex(value)
	if match == nil {
		return false
	}
	for i := 0; i < len(match)/2 && i < 9; i++ {
		if match[2*i] >= 0 {
			tx.CaptureField(i, value[match[2*i]:match[2*i+1]])
		} else {
			tx.CaptureField(i, "")
		}
	}
	return true
}

func (o *rxBinary) Evaluate(tx plugintypes.TransactionState, value string) bool {
	if !tx.Capturing() {
		return o.re.MatchString(value)
	}
	match := o.re.FindStringSubmatch(value)
	if len(match) == 0 {
		return false
	}
	for i, c := range match {
		if i == 9 {
			break
		}
		tx.CaptureField(i, c)
	}
	return true
}

// matchesArbitraryBytes is Coraza's (internal/operators/rx.go): whether the
// pattern's \xNN escapes spell bytes that are not valid UTF-8.
func matchesArbitraryBytes(expr string) bool {
	decoded := make([]byte, 0, len(expr))
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c != '\\' {
			decoded = append(decoded, c)
			continue
		}
		if i+3 >= len(expr) {
			decoded = append(decoded, expr[i:]...)
			break
		}
		if expr[i+1] != 'x' {
			decoded = append(decoded, expr[i])
			continue
		}
		sub := expr[i:]
		advance := 3
		if len(sub) >= 6 && sub[2] == '{' {
			if end := strings.IndexByte(sub, '}'); end != -1 {
				sub = `\x` + sub[3:end]
				advance = end
			}
		}
		v, mb, _, err := strconv.UnquoteChar(sub, 0)
		if err != nil || mb {
			decoded = append(decoded, expr[i])
			continue
		}
		decoded = append(decoded, byte(v))
		i += advance
	}
	return !utf8.Valid(decoded)
}
