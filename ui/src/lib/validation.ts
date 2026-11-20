/** Validate an IPv4 address with optional CIDR notation.
 *  Each octet must be 0-255, CIDR must be 0-32 if present. */
export function isValidIP(value: string): boolean {
  const parts = value.split('/');
  if (parts.length > 2) return false;
  const octets = parts[0].split('.');
  if (octets.length !== 4) return false;
  const validOctets = octets.every(o => {
    const n = parseInt(o, 10);
    return /^\d{1,3}$/.test(o) && n >= 0 && n <= 255;
  });
  if (!validOctets) return false;
  if (parts[1] !== undefined) {
    const cidr = parseInt(parts[1], 10);
    return /^\d{1,2}$/.test(parts[1]) && cidr >= 0 && cidr <= 32;
  }
  return true;
}

/** An IPv4 address as Go's netip parses it inside an IPv6 one: four decimal
 *  fields from 0 to 255, with no leading zero. */
function isNetipIPv4(s: string): boolean {
  const fields = s.split('.');
  return fields.length === 4 && fields.every((f) => /^(0|[1-9]\d{0,2})$/.test(f) && Number(f) <= 255);
}

/** An IPv6 address as netip.ParseAddr takes it: eight groups of 1 to 4 hex
 *  digits, one "::" standing for at least one zero group, the last two
 *  groups optionally written as an IPv4 address, and an optional non-empty
 *  zone after "%". */
function isNetipIPv6(value: string, zoneAllowed: boolean): boolean {
  let s = value;
  const pct = s.indexOf('%');
  if (pct !== -1) {
    if (!zoneAllowed || pct === s.length - 1) return false;
    s = s.slice(0, pct);
  }
  const halves = s.split('::');
  if (halves.length > 2) return false;
  // Groups in one side of the "::", or null when a field is not one. An
  // embedded IPv4 address is taken only at the very end of the address.
  const count = (part: string, last: boolean): number | null => {
    if (part === '') return 0;
    const fields = part.split(':');
    let n = 0;
    for (let i = 0; i < fields.length; i++) {
      const f = fields[i];
      if (last && i === fields.length - 1 && f.includes('.')) {
        if (!isNetipIPv4(f)) return null;
        n += 2;
      } else if (/^[0-9a-fA-F]{1,4}$/.test(f)) {
        n += 1;
      } else {
        return null;
      }
    }
    return n;
  };
  if (halves.length === 1) return count(s, true) === 8;
  const left = count(halves[0], false);
  const right = count(halves[1], true);
  return left !== null && right !== null && left + right <= 7;
}

/** An IP address or network the backend takes on the IP lists: the same
 *  answer as netguard.IsValidCIDR (backend-go/internal/netguard), which is
 *  netip.ParsePrefix or else netip.ParseAddr. IPv6 is checked as netip does;
 *  IPv4 keeps isValidIP, which is a little wider (it takes a leading zero),
 *  so the backend's own refusal covers the rest. isValidIP stays IPv4 only,
 *  because the egress form relies on it. */
export function isValidIPOrNetwork(value: string): boolean {
  if (!value.includes(':')) return isValidIP(value);
  // A network: the address (no zone) and a prefix length from 0 to 128,
  // written without a leading zero.
  const slash = value.lastIndexOf('/');
  if (slash !== -1) {
    const bits = value.slice(slash + 1);
    if (/^(0|[1-9]\d{0,2})$/.test(bits) && Number(bits) <= 128 && isNetipIPv6(value.slice(0, slash), false)) return true;
  }
  // An address; its zone may hold any character, a "/" included.
  return isNetipIPv6(value, true);
}

/** Validate a domain name per RFC 1035.
 *  Max 253 chars total, labels 1-63 chars, valid characters. */
export function isValidDomain(value: string): boolean {
  if (value.length === 0 || value.length > 253) return false;
  const labels = value.split('.');
  if (labels.length < 2) return false;
  return labels.every(
    l => l.length > 0 && l.length <= 63 && /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(l)
  );
}

/** Validate password strength: 8+ characters, at least one digit, at least
 *  one special character. The backend is the source of truth and this
 *  mirrors it (backend-go/internal/handlers/auth.go ChangePassword): `min=8`
 *  counts characters (runes), not UTF-16 units; pwdStrong is [0-9]; and
 *  pwdSpecial is [^a-zA-Z0-9], so any character that is not an ASCII letter
 *  or digit counts, a hyphen, a space or an accented letter included. */
export function validatePassword(pwd: string): { valid: boolean; hasLength: boolean; hasNumber: boolean; hasSpecial: boolean } {
  const hasLength = [...pwd].length >= 8;
  const hasNumber = /[0-9]/.test(pwd);
  const hasSpecial = /[^a-zA-Z0-9]/.test(pwd);
  return { valid: hasLength && hasNumber && hasSpecial, hasLength, hasNumber, hasSpecial };
}

/** Parse geo-blocking country input into valid 2-letter codes. */
export function parseGeoCountries(input: string): string[] {
  return input
    .split(/[\s,]+/)
    .map(c => c.trim().toUpperCase())
    .filter(c => c.length === 2 && /^[A-Z]{2}$/.test(c));
}

/** 1 to 3650 whole days, as POST /api/logs/clear-old takes them; null otherwise. */
export function oldLogDays(text: string): number | null {
  if (!/^\d+$/.test(text.trim())) return null;
  const n = Number(text.trim());
  return n >= 1 && n <= 3650 ? n : null;
}
