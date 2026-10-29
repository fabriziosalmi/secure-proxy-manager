/**
 * AddEntries: every way an entry reaches a list, behind the page's one
 * primary button. A blocked list takes a single entry, a pasted list, a URL,
 * one of the Popular lists and (IPs only) a country's address blocks; an
 * allowed list takes a single entry or a pasted list, sent to its own import
 * ({list}/import), because blacklists/import feeds the blocked lists only.
 *
 * Every write records its source on the backend: Manual for a single entry,
 * Pasted list for pasted text on any list, the URL (and the Popular list's
 * name) for an import, the country for a geo-block.
 *
 * Refusals are shown in the panel as the backend words them, the domain
 * limit (SPM_DNS_BLOCKLIST_MAX_DOMAINS) included: an import that would pass
 * it is refused whole.
 */
import { useId, useRef, useState, type FormEvent, type ReactNode } from 'react';
import toast from 'react-hot-toast';
import { Download, Loader2 } from 'lucide-react';
import { api, getErrorMessage } from '../../lib/api';
import { formatCount } from '../../lib/format';
import { isValidDomain, isValidIP, parseGeoCountries } from '../../lib/validation';
import { cn } from '../../lib/utils';
import { Button } from '../ui/Button';
import { Section } from '../ui/Section';
import { SegmentedControl } from '../ui/SegmentedControl';
import { methodsFor, type AddMethod, type ListDef } from './lists';
import { popularDomainLists, popularIpLists } from './popularLists';
import { DomainScopeHelp } from '../ui/DomainScopeHelp';

const METHOD_LABELS: Record<AddMethod, string> = {
  single: 'Single entry',
  paste: 'Paste a list',
  url: 'Import from URL',
  popular: 'Popular lists',
  geo: 'Geo-block',
};

const FIELD =
  'h-9 w-full min-w-0 rounded-control border border-line-strong bg-surface px-3 text-sm text-ink placeholder:text-ink-subtle ' +
  'focus:border-accent focus:outline-hidden focus:ring-2 focus:ring-accent/30';

function Field({ id, label, hint, children }: { id: string; label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-1 flex-col gap-1.5">
      <label htmlFor={id} className="text-[13px] font-medium text-ink-secondary">{label}</label>
      {children}
      {hint && <p id={`${id}-hint`} className="text-xs text-ink-muted">{hint}</p>}
    </div>
  );
}

function importMessage(data: { added?: number; skipped?: number; bogon_skipped?: number } | undefined, prefix = 'Added'): string {
  const added = data?.added ?? 0;
  const skipped = data?.skipped ?? 0;
  const bogon = data?.bogon_skipped ?? 0;
  let msg = `${prefix} ${formatCount(added)} ${added === 1 ? 'entry' : 'entries'}`;
  if (skipped > 0) msg += `, ${formatCount(skipped)} skipped (already listed or not valid)`;
  if (bogon > 0) msg += `; ${formatCount(bogon)} of them private or LAN ranges, which cannot be blocked`;
  return msg;
}

/** The refusals named in the panel; the count covers the rest. */
const REFUSALS_SHOWN = 5;

interface AllowedImport {
  added?: number;
  skipped?: number;
  refused?: number;
  refusals?: { entry: string; reason: string }[];
}

/** What a paste on an allowed list did, with the reason for each refused line it names. */
function allowedPasteMessage(data: AllowedImport | undefined, label: string): { text: string; refused: boolean } {
  const added = data?.added ?? 0;
  const skipped = data?.skipped ?? 0;
  const refused = data?.refused ?? 0;
  let text = `Added ${formatCount(added)} ${added === 1 ? 'entry' : 'entries'} to ${label}`;
  if (skipped > 0) text += `, ${formatCount(skipped)} already listed`;
  if (refused === 0) return { text, refused: false };
  const named = (data?.refusals ?? []).slice(0, REFUSALS_SHOWN).map((x) => x.reason);
  text += `; ${formatCount(refused)} refused: ${named.join('; ')}`;
  if (refused > named.length) text += `; and ${formatCount(refused - named.length)} more`;
  return { text: `${text}.`, refused: true };
}

export interface AddEntriesProps {
  list: ListDef;
  method: AddMethod;
  onMethodChange: (m: AddMethod) => void;
  /** Called after any write that may have changed the list. */
  onChanged: () => void;
  onClose: () => void;
}

export function AddEntries({ list, method, onMethodChange, onChanged, onClose }: AddEntriesProps) {
  const ids = useId();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<AddMethod | string | null>(null);
  // The handler's own guard: a second submit while one is in flight is
  // refused even if the disabled attribute is ever dropped (#219, M8).
  const inFlight = useRef(false);

  const [value, setValue] = useState('');
  const [desc, setDesc] = useState('');
  const [text, setText] = useState('');
  const [url, setUrl] = useState('');
  const [countries, setCountries] = useState('');

  const run = async (key: AddMethod | string, work: () => Promise<string | null>) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(key);
    setError(null);
    try {
      const ok = await work();
      if (ok) toast.success(ok, { duration: 6000 });
      onChanged();
    } catch (err) {
      setError(getErrorMessage(err, 'The request failed'));
    } finally {
      inFlight.current = false;
      setBusy(null);
    }
  };

  const addSingle = (e: FormEvent) => {
    e.preventDefault();
    const v = value.trim();
    if (!v) return;
    // The backend's refusal on Allowed domains (allowedDomainValue), said
    // before the request: a leading dot or "*." would read as "and its
    // subdomains", and an allowed name covers none.
    const exact = v.replace(/^(\*\.)?\.*/, '');
    if (list.allowed && list.field === 'domain' && exact !== v && isValidDomain(exact)) {
      setError(`"${v}" is not an exact name: write ${exact}. A domain exception takes that same name off Blocked domains, however it is written there, and covers no name under it.`);
      return;
    }
    if (list.field === 'ip' ? !isValidIP(v) : !isValidDomain(v)) {
      setError(list.field === 'ip'
        ? `"${v}" is not an IPv4 address or network: four numbers from 0 to 255, optionally /0 to /32.`
        : `"${v}" is not a domain name: labels of letters, digits and hyphens separated by dots.`);
      return;
    }
    void run('single', async () => {
      await api.post(list.path, { [list.field]: v, description: desc.trim() });
      setValue('');
      setDesc('');
      return `Added ${v} to ${list.label}`;
    });
  };

  const addPaste = (e: FormEvent) => {
    e.preventDefault();
    if (!text.trim()) return;
    if (list.allowed) {
      // The allowed list's own import, never blacklists/import (which feeds
      // the blocked lists): one pasted-list source, each line checked as a
      // single entry is, and each refusal named with its reason.
      void run('paste', async () => {
        const r = await api.post(`${list.path}/import`, { content: text });
        setText('');
        const msg = allowedPasteMessage(r.data?.data, list.label);
        if (msg.refused) {
          setError(msg.text);
          return null;
        }
        return msg.text;
      });
      return;
    }
    void run('paste', async () => {
      const r = await api.post('blacklists/import', { type: list.field, content: text });
      setText('');
      return importMessage(r.data?.data);
    });
  };

  const addUrl = (e: FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    void run('url', async () => {
      const r = await api.post('blacklists/import', { type: list.field, url: url.trim() });
      setUrl('');
      return importMessage(r.data?.data, 'Imported');
    });
  };

  const addPopular = (name: string, listUrl: string) =>
    run(name, async () => {
      const r = await api.post('blacklists/import', { type: list.field, url: listUrl, name });
      return `${name}: ${importMessage(r.data?.data).toLowerCase()}`;
    });

  const addGeo = (e: FormEvent) => {
    e.preventDefault();
    // The shared, tested parser: "12" and "A1" are not country codes (#219, M10b).
    const codes = parseGeoCountries(countries);
    if (codes.length === 0) {
      setError('Enter two-letter ISO country codes, such as CN, RU, KP.');
      return;
    }
    void run('geo', async () => {
      const r = await api.post('blacklists/import-geo', { countries: codes });
      const d = r.data?.data ?? {};
      setCountries('');
      const msg = `Imported ${formatCount(d.imported ?? 0)} address blocks for ${formatCount(d.countries_imported ?? 0)} of ${formatCount(d.countries_requested ?? codes.length)} countries`;
      if (Array.isArray(d.errors) && d.errors.length > 0) {
        setError(`${msg}. Not imported: ${d.errors.join('; ')}`);
        return null;
      }
      return msg;
    });
  };

  const methods = methodsFor(list);
  const popular = list.field === 'ip' ? popularIpLists : popularDomainLists;
  const errorBox = error && (
    <p role="alert" className="rounded-control border border-danger-line bg-danger-subtle px-3 py-2 text-sm text-danger">{error}</p>
  );

  let body: ReactNode;
  if (method === 'single') {
    body = (
      <form onSubmit={addSingle} className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <Field id={`${ids}-value`} label={list.entryLabel}>
          <input id={`${ids}-value`} className={cn(FIELD, 'font-mono')} value={value} onChange={(e) => setValue(e.target.value)}
            placeholder={list.entryPlaceholder} autoComplete="off" spellCheck={false} required />
        </Field>
        <Field id={`${ids}-desc`} label="Description (optional)">
          <input id={`${ids}-desc`} className={FIELD} value={desc} onChange={(e) => setDesc(e.target.value)} maxLength={500}
            placeholder={list.allowed ? 'Why it is allowed' : 'Why it is blocked'} />
        </Field>
        <Button type="submit" variant="primary" disabled={busy === 'single'}>{busy === 'single' ? 'Adding...' : 'Add entry'}</Button>
      </form>
    );
  } else if (method === 'paste') {
    body = (
      <form onSubmit={addPaste} className="flex flex-col gap-3">
        <Field
          id={`${ids}-text`}
          label="Entries, one per line"
          hint={list.allowed
            ? 'One entry per line; lines starting with # are ignored. Entries already listed are skipped, and an entry that is not valid is refused with the reason.'
            : 'Lines starting with # or ; are ignored, and hosts-file lines work: the last field of a line is the entry. Entries already listed or not valid are skipped.'}
        >
          <textarea id={`${ids}-text`} aria-describedby={`${ids}-text-hint`} value={text} onChange={(e) => setText(e.target.value)} rows={6} required
            spellCheck={false}
            placeholder={list.field === 'ip' ? 'e.g. 203.0.113.7\n198.51.100.0/24' : 'e.g. ads.example.com\ntracker.example.net'}
            className={cn(FIELD, 'h-auto resize-y py-2 font-mono')} />
        </Field>
        <div><Button type="submit" variant="primary" disabled={busy === 'paste'}>{busy === 'paste' ? 'Adding...' : 'Add pasted entries'}</Button></div>
      </form>
    );
  } else if (method === 'url') {
    body = (
      <form onSubmit={addUrl} className="flex flex-col gap-3 sm:flex-row sm:items-start">
        <Field
          id={`${ids}-url`}
          label="List URL"
          hint={`A plain text file with one ${list.field === 'ip' ? 'address or network' : 'domain'} per line, or a hosts file. The backend fetches it; addresses on private networks are refused.`}
        >
          <input id={`${ids}-url`} type="url" aria-describedby={`${ids}-url-hint`} className={FIELD} value={url} onChange={(e) => setUrl(e.target.value)}
            placeholder="e.g. https://raw.githubusercontent.com/..." required />
        </Field>
        <Button type="submit" variant="primary" className="sm:mt-[26px]" disabled={busy === 'url'}>{busy === 'url' ? 'Importing...' : 'Import list'}</Button>
      </form>
    );
  } else if (method === 'popular') {
    body = (
      <ul className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {popular.map((p) => (
          <li key={p.url} className="flex min-w-0 flex-col gap-2 rounded-control border border-line p-4">
            <h3 className="text-sm font-semibold text-ink">{p.name}</h3>
            <p className="flex-1 text-[13px] text-ink-muted">{p.desc}</p>
            <div>
              <Button
                size="sm"
                aria-label={`Import ${p.name}`}
                disabled={busy !== null}
                onClick={() => { void addPopular(p.name, p.url); }}
                icon={busy === p.name ? <Loader2 className="animate-spin" /> : <Download />}
              >
                {busy === p.name ? 'Importing...' : 'Import'}
              </Button>
            </div>
          </li>
        ))}
      </ul>
    );
  } else {
    body = (
      <form onSubmit={addGeo} className="flex flex-col gap-3 sm:flex-row sm:items-start">
        <Field
          id={`${ids}-geo`}
          label="Country codes"
          hint="Two-letter ISO codes, separated by commas or spaces. Every known IPv4 block of each country is added to Blocked IPs."
        >
          <input id={`${ids}-geo`} aria-describedby={`${ids}-geo-hint`} className={FIELD} value={countries}
            onChange={(e) => setCountries(e.target.value.toUpperCase())} placeholder="e.g. CN, RU, KP" required />
        </Field>
        <Button type="submit" variant="primary" className="sm:mt-[26px]" disabled={busy === 'geo'}>{busy === 'geo' ? 'Importing...' : 'Download and block IPs'}</Button>
      </form>
    );
  }

  return (
    <Section title={`Add to ${list.label}`} description="Each entry records where it came from, so a whole import can be removed later.">
      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="max-w-full overflow-x-auto">
            <SegmentedControl<AddMethod>
              label="How to add"
              options={methods.map((m) => ({ value: m, label: METHOD_LABELS[m] }))}
              value={method}
              onChange={(m) => { setError(null); onMethodChange(m); }}
              size="sm"
              // One line per option: on a phone the control scrolls sideways
              // in its own box instead of breaking "Single entry" in two.
              className="whitespace-nowrap"
            />
          </div>
          <Button size="sm" variant="ghost" onClick={onClose}>Close</Button>
        </div>
        {errorBox}
        {body}
        {list.field === 'domain' && <DomainScopeHelp />}
      </div>
    </Section>
  );
}
