// Asset Tags: map IPs to human-readable names
// Stored in localStorage for simplicity (no backend needed)

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

export function getAssetTags(): AssetTag[] {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  } catch { return []; }
}

export function setAssetTags(tags: AssetTag[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(tags));
}

export function getTagForIp(ip: string): AssetTag | undefined {
  return getAssetTags().find(t => t.ip === ip);
}

export function addAssetTag(ip: string, name: string): void {
  const tags = getAssetTags();
  const existing = tags.findIndex(t => t.ip === ip);
  const color = COLORS[tags.length % COLORS.length];
  if (existing >= 0) {
    tags[existing] = { ...tags[existing], name };
  } else {
    tags.push({ ip, name, color });
  }
  setAssetTags(tags);
}

export function removeAssetTag(ip: string): void {
  setAssetTags(getAssetTags().filter(t => t.ip !== ip));
}

/** Render helper: returns tag name or original IP */
export function resolveIp(ip: string): string {
  const tag = getTagForIp(ip);
  return tag ? tag.name : ip;
}
