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

/** Validate password strength: 8+ chars, at least one digit, at least one special char. */
export function validatePassword(pwd: string): { valid: boolean; hasLength: boolean; hasNumber: boolean; hasSpecial: boolean } {
  const hasLength = pwd.length >= 8;
  const hasNumber = /\d/.test(pwd);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(pwd);
  return { valid: hasLength && hasNumber && hasSpecial, hasLength, hasNumber, hasSpecial };
}

/** Parse geo-blocking country input into valid 2-letter codes. */
export function parseGeoCountries(input: string): string[] {
  return input
    .split(/[\s,]+/)
    .map(c => c.trim().toUpperCase())
    .filter(c => c.length === 2 && /^[A-Z]{2}$/.test(c));
}
