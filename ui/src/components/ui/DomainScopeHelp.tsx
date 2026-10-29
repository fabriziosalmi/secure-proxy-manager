/**
 * DomainScopeHelp: what a domain on a list covers, in the same words on every
 * form that takes domains (Blocked domains, Domain exceptions, the
 * default-deny allowlist). A leading dot meant three things on three lists:
 * the name and its subdomains on the egress list, the name itself on Blocked
 * domains, a refusal on the exceptions. The forms no longer ask for it; only
 * the default-deny allowlist covers subdomains, through its checkbox.
 */
export const DOMAIN_SCOPE = 'A domain covers that exact name only: example.com does not cover www.example.com.';

export function DomainScopeHelp({ subdomains = false }: { subdomains?: boolean }) {
  return (
    <p data-help="domain-scope" className="text-[13px] text-ink-muted">
      {DOMAIN_SCOPE}{' '}
      {subdomains
        ? 'Tick Include subdomains to cover example.com and every name under it.'
        : 'This list has no way to cover the names under it.'}
    </p>
  );
}
