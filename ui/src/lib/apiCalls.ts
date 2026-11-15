/**
 * The API operations a piece of UI source calls, read from the text: every
 * api.get/post/put/delete/patch and getData call, and every string that starts
 * with /api/ (links, downloads, the live log socket). The surfaces test compares what it
 * finds with the operations docs/public/openapi.json marks as reachable from
 * the UI (x-spm-surfaces), both ways.
 *
 * A path built from a template keeps its literal parts; a `${...}` inside it
 * stands for one path segment, and a `${...}` the path starts with is looked
 * up in `prefixes` (the list paths a variable can hold). A call whose path is
 * neither a literal, a template nor a known variable is returned in
 * `unresolved`, so a new kind of call cannot go uncounted.
 */

export type Method = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

export interface ApiCall {
  method: Method;
  /** Path below the host, starting /api/, with `{}` for a segment the call fills in. */
  path: string;
  where: string;
}

export interface Extracted {
  calls: ApiCall[];
  unresolved: string[];
}

const CALL = /\b(?:api\.(get|post|put|delete|patch)|(getData))\s*(<)?/g;

/** Skip a balanced <...> generic argument starting at i (text[i] === '<'); returns the index after it. */
function skipGeneric(text: string, i: number): number {
  let depth = 0;
  for (; i < text.length; i++) {
    if (text[i] === '<') depth++;
    else if (text[i] === '>' && text[i - 1] !== '=') {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return i;
}

/** Read the first argument of a call whose '(' is at i: the raw text up to the top-level ',' or ')'. */
function firstArgument(text: string, i: number): string {
  let depth = 0;
  let quote: string | null = null;
  const start = i + 1;
  for (i = start; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = null;
      else if (quote === '`' && c === '$' && text[i + 1] === '{') {
        // A template expression: skip it whole.
        let d = 0;
        for (i += 1; i < text.length; i++) {
          if (text[i] === '{') d++;
          else if (text[i] === '}' && --d === 0) break;
        }
      }
      continue;
    }
    if (c === '\'' || c === '"' || c === '`') quote = c;
    else if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) return text.slice(start, i).trim();
      depth--;
    } else if (c === ',' && depth === 0) return text.slice(start, i).trim();
  }
  return text.slice(start).trim();
}

/** The paths a first argument can stand for, below /api/, or null when it cannot be read. */
function pathsOf(arg: string, prefixes: Record<string, readonly string[]>): string[] | null {
  const literal = /^(['"])([^'"]*)\1$/.exec(arg);
  if (literal) return [literal[2]];
  const template = /^`([^`]*)`$/.exec(arg);
  if (template) {
    let body = template[1];
    let heads = [''];
    const lead = /^\$\{([^}]+)\}/.exec(body);
    if (lead) {
      const known = prefixes[lead[1].trim()];
      if (!known) return null;
      heads = [...known];
      body = body.slice(lead[0].length);
    }
    const rest = body.replace(/\$\{[^}]*\}/g, '{}');
    return heads.map((h) => h + rest);
  }
  const known = prefixes[arg];
  return known ? [...known] : null;
}

/** '/ws-token?x=1' -> '/api/ws-token'; a segment holding a {} placeholder becomes {}. */
export function normalise(path: string): string {
  let p = path.split('?')[0].split('#')[0];
  if (!p.startsWith('/api/')) p = '/api/' + p.replace(/^\/+/, '');
  return p
    .split('/')
    .map((s) => (s.includes('{}') ? '{}' : s))
    .join('/')
    .replace(/\/+$/, '');
}

/**
 * The source with its comments blanked (newlines kept, so line numbers hold):
 * a path named in a comment is not a call. Strings and templates are kept
 * whole; a '//' after a backslash is a regular expression, not a comment.
 */
export function stripComments(text: string): string {
  let out = '';
  let quote: string | null = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      out += c;
      if (c === '\\') { out += text[++i] ?? ''; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '/' && text[i + 1] === '/' && text[i - 1] !== '\\') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
      continue;
    }
    if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      const stop = end === -1 ? text.length : end + 2;
      out += text.slice(i, stop).replace(/[^\n]/g, ' ');
      i = stop - 1;
      continue;
    }
    if (c === '\'' || c === '"' || c === '`') quote = c;
    out += c;
  }
  return out;
}

export function extractApiCalls(
  sources: Record<string, string>,
  prefixes: Record<string, readonly string[]>,
  /** "file: argument" pairs that pass a caller's path through (getData's own api.get(path)). */
  passThrough: readonly string[] = [],
): Extracted {
  const calls: ApiCall[] = [];
  const unresolved: string[] = [];
  for (const [file, raw] of Object.entries(sources)) {
    if (file.endsWith('/lib/apiCalls.ts')) continue;
    const text = stripComments(raw);
    for (const m of text.matchAll(CALL)) {
      let i = m.index + m[0].length;
      if (m[3]) i = skipGeneric(text, i - 1);
      while (/\s/.test(text[i] ?? '')) i++;
      if (text[i] !== '(') continue;
      // The helper's own definition, not a call.
      if (/function\s+$/.test(text.slice(Math.max(0, m.index - 12), m.index))) continue;
      const method = (m[1] ?? 'get').toUpperCase() as Method;
      const arg = firstArgument(text, i);
      const line = text.slice(0, m.index).split('\n').length;
      const paths = pathsOf(arg, prefixes);
      if (!paths) {
        if (passThrough.some((p) => file.endsWith(p.split(': ')[0]) && p.split(': ')[1] === arg)) continue;
        unresolved.push(`${file}:${line}: ${m[0]}(${arg})`);
        continue;
      }
      for (const p of paths) calls.push({ method, path: normalise(p), where: `${file}:${line}` });
    }
    // Links, downloads and the log socket: '/api/...' inside any string.
    // The string must start with the path, or the path must follow a
    // template expression (`${origin}/api/ws/logs`): "GET /api/x failed" in a
    // message names a route, it does not call it.
    for (const m of text.matchAll(/(?:['"`]|\})(\/api\/[a-z0-9/_{}$-]+(?:\.[a-z]+)?)/g)) {
      const raw = m[1].replace(/\$\{[^}]*\}/g, '{}');
      const line = text.slice(0, m.index).split('\n').length;
      calls.push({ method: 'GET', path: normalise(raw), where: `${file}:${line}` });
    }
  }
  return { calls, unresolved };
}

/**
 * How an OpenAPI path like /api/ip-blacklist/{id} matches a call path: null
 * when it does not, otherwise the number of segments a parameter took. A call
 * segment {} matches only a parameter; a literal one (clear-all, unrecorded)
 * matches the same literal or a parameter, and the caller keeps the match with
 * the fewest parameters, so DELETE .../clear-all is not also DELETE .../{id}.
 */
export function matchScore(openapiPath: string, callPath: string): number | null {
  const a = openapiPath.split('/');
  const b = callPath.split('/');
  if (a.length !== b.length) return null;
  let params = 0;
  for (let k = 0; k < a.length; k++) {
    const param = a[k].startsWith('{');
    if (b[k] === '{}') {
      if (!param) return null;
      params++;
    } else if (a[k] !== b[k]) {
      if (!param) return null;
      params++;
    }
  }
  return params;
}
