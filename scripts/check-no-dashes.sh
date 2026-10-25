#!/usr/bin/env bash
# Fail if an em dash (U+2014) or an en dash (U+2013) appears in the UI source
# (ui/src, *.ts and *.tsx, tests included), in docs/, in any Markdown file, or
# in the other text a user reads: the Squid error pages (proxy/error-pages,
# served to every client a rule blocks), the UI's index.html and the scripts
# and images in ui/public (the fonts there are third-party files and are not
# checked), and .env.example, the file an operator copies to .env and edits.
#
# The UI used a bare em dash as the placeholder for a missing value, which
# reads like a value and does not say what is missing, and as punctuation in
# toasts, labels and empty states. The docs were cleaned of both dashes in
# #409. This keeps them from coming back. A test that needs the character can
# write it as a JavaScript escape of its code point (backslash, u, 2014).
#
# Same shape as check-version-sync.sh and check-image-pins.sh: turn a rule
# that exists only in someone's head into a check that fails.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

em=$(printf '\342\200\224')
en=$(printf '\342\200\223')

# Tracked files plus new ones not yet added, so a local run sees a file
# before it is committed. Paths deleted from the work tree are skipped.
files=()
while IFS= read -r -d '' f; do
    [ -f "$f" ] && files+=("$f")
done < <(git ls-files -z --cached --others --exclude-standard -- \
    'ui/src/*.ts' 'ui/src/*.tsx' 'docs/*' '*.md' \
    'proxy/error-pages/*' 'ui/index.html' 'ui/public/*.js' 'ui/public/*.svg' \
    '.env.example')

if [ "${#files[@]}" -eq 0 ]; then
    echo "FAIL: found no files to check; is this a checkout of the repository?" >&2
    exit 1
fi

# grep: 0 = a dash was found, 1 = none, anything else = grep itself failed.
# The last case must fail too, or an unreadable file would pass as clean.
rc=0
hits=$(LC_ALL=C grep -n -H -I -e "$em" -e "$en" -- "${files[@]}") || rc=$?
case $rc in
    0)
        echo "FAIL: em dash (U+2014) or en dash (U+2013) found:" >&2
        echo "$hits" >&2
        echo "  Use a colon, a comma, a full stop or parentheses instead. For a" >&2
        echo "  missing value, say what is missing (\"Not reported\", \"Not collected\")." >&2
        exit 1
        ;;
    1)
        echo "OK: no em or en dashes in ui/src, docs/, Markdown, proxy/error-pages, ui/public or .env.example (${#files[@]} files)"
        ;;
    *)
        echo "FAIL: grep exited $rc while scanning for dashes" >&2
        exit 1
        ;;
esac
