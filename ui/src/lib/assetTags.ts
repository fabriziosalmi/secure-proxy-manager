// Asset Tags: map IPs to human-readable names
// Stored in localStorage for simplicity (no backend needed).
//
// The value is parsed from localStorage ONCE and held in an in-memory cache so
// that hot render paths (IpBadge renders once per row in the streaming Logs
// table) don't re-`JSON.parse` on every render. Writes update the cache and
// notify subscribers; cross-tab writes invalidate the cache via the `storage`
// event. Consume it with `useSyncExternalStore(subscribeAssetTags, getAssetTagsSnapshot)`.

const STORAGE_KEY = 'asset_tags';

export interface AssetTag {
  ip: string;
  name: string;
  color?: string;
}

const COLORS = [
  '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
  '#ec4899', '#06b6d4', '#f97316', '#14b8a6', '#6366f1',
];

let cache: AssetTag[] | null = null;
const listeners = new Set<() => void>();

function read(): AssetTag[] {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  } catch { return []; }
}

function emit(): void {
  listeners.forEach(l => l());
}

/** Returns the cached tag list (parsed once). Reference is stable between writes. */
export function getAssetTags(): AssetTag[] {
  if (cache === null) cache = read();
  return cache;
}

export function setAssetTags(tags: AssetTag[]): void {
  cache = tags;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(tags));
  emit();
}

/** useSyncExternalStore subscribe: fires on any tag write (this tab or another). */
export function subscribeAssetTags(cb: () => void): () => void {
  listeners.add(cb);
  return () => { listeners.delete(cb); };
}

/** useSyncExternalStore getSnapshot: stable reference until the next write. */
export function getAssetTagsSnapshot(): AssetTag[] {
  return getAssetTags();
}

// Keep tabs in sync: a write in another tab must invalidate our cache.
if (typeof window !== 'undefined') {
  window.addEventListener('storage', (e) => {
    if (e.key === STORAGE_KEY) { cache = read(); emit(); }
  });
}

export function getTagForIp(ip: string): AssetTag | undefined {
  return getAssetTags().find(t => t.ip === ip);
}

export function addAssetTag(ip: string, name: string): void {
  const tags = getAssetTags();
  const existing = tags.findIndex(t => t.ip === ip);
  const color = COLORS[tags.length % COLORS.length];
  if (existing >= 0) {
    // Copy-on-write so subscribers get a fresh reference and re-render.
    const next = tags.slice();
    next[existing] = { ...next[existing], name };
    setAssetTags(next);
  } else {
    setAssetTags([...tags, { ip, name, color }]);
  }
}

export function removeAssetTag(ip: string): void {
  setAssetTags(getAssetTags().filter(t => t.ip !== ip));
}
