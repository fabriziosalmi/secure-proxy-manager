import { memo, useState, useSyncExternalStore } from 'react';
import { Tag, X, Check } from 'lucide-react';
import { subscribeAssetTags, getAssetTagsSnapshot, addAssetTag, removeAssetTag } from '../lib/assetTags';

interface IpBadgeProps {
  ip: string;
  className?: string;
}

function IpBadgeImpl({ ip, className = '' }: IpBadgeProps) {
  const [editing, setEditing] = useState(false);
  const [tagName, setTagName] = useState('');
  // Read the tag map from the shared store — parsed once, not per render.
  // Writes (add/remove) notify subscribers, so no manual forceUpdate is needed.
  const tags = useSyncExternalStore(subscribeAssetTags, getAssetTagsSnapshot);
  const tag = tags.find(t => t.ip === ip);

  if (editing) {
    return (
      <span className="inline-flex items-center gap-1">
        <input
          autoFocus
          value={tagName}
          aria-label={`Name for ${ip}`}
          onChange={e => setTagName(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' && tagName.trim()) {
              addAssetTag(ip, tagName.trim());
              setEditing(false);
            }
            if (e.key === 'Escape') setEditing(false);
          }}
          placeholder="Name this IP..."
          className="w-24 px-1.5 py-0.5 bg-background border border-primary/40 rounded text-[11px] outline-none focus:border-primary"
        />
        <button type="button" aria-label={`Save tag for ${ip}`} onClick={() => {
          if (tagName.trim()) { addAssetTag(ip, tagName.trim()); setEditing(false); }
        }} className="text-emerald-500 hover:text-emerald-400"><Check className="w-3 h-3" /></button>
        <button type="button" aria-label="Cancel editing tag" onClick={() => setEditing(false)} className="text-muted-foreground hover:text-foreground"><X className="w-3 h-3" /></button>
      </span>
    );
  }

  if (tag) {
    return (
      <span className={`inline-flex items-center gap-1 group ${className}`}>
        <span className="font-mono font-bold" title={ip}>{ip}</span>
        <button
          type="button"
          className="text-[10px] px-1.5 py-0.5 rounded-full font-medium cursor-pointer hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
          style={{ backgroundColor: (tag.color || '#3b82f6') + '20', color: tag.color || '#3b82f6', border: `1px solid ${(tag.color || '#3b82f6')}30` }}
          onClick={(e) => { e.stopPropagation(); setTagName(tag.name); setEditing(true); }}
          title={`Click to edit — ${ip}`}
          aria-label={`Edit tag for ${ip}`}
        >
          {tag.name}
        </button>
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); removeAssetTag(ip); }}
          className="hidden group-hover:inline text-muted-foreground hover:text-destructive"
          title="Remove tag"
          aria-label={`Remove tag from ${ip}`}
        ><X className="w-2.5 h-2.5" /></button>
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center gap-1 group ${className}`}>
      <span className="font-mono font-bold">{ip}</span>
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); setTagName(''); setEditing(true); }}
        className="hidden group-hover:inline text-muted-foreground hover:text-primary"
        title="Tag this IP"
        aria-label={`Tag ${ip}`}
      >
        <Tag className="w-2.5 h-2.5" />
      </button>
    </span>
  );
}

export const IpBadge = memo(IpBadgeImpl);
