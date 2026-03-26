import { useState } from 'react';
import { Tag, X, Check } from 'lucide-react';
import { getTagForIp, addAssetTag, removeAssetTag } from '../lib/assetTags';

interface IpBadgeProps {
  ip: string;
  className?: string;
}

export function IpBadge({ ip, className = '' }: IpBadgeProps) {
  const [editing, setEditing] = useState(false);
  const [tagName, setTagName] = useState('');
  const [, forceUpdate] = useState(0);

  const tag = getTagForIp(ip);

  if (editing) {
    return (
      <span className="inline-flex items-center gap-1">
        <input
          autoFocus
          value={tagName}
          onChange={e => setTagName(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' && tagName.trim()) {
              addAssetTag(ip, tagName.trim());
              setEditing(false);
              forceUpdate(n => n + 1);
            }
            if (e.key === 'Escape') setEditing(false);
          }}
          placeholder="Name this IP..."
          className="w-24 px-1.5 py-0.5 bg-background border border-primary/40 rounded text-[11px] outline-none focus:border-primary"
        />
        <button type="button" onClick={() => {
          if (tagName.trim()) { addAssetTag(ip, tagName.trim()); setEditing(false); forceUpdate(n => n + 1); }
        }} className="text-emerald-500 hover:text-emerald-400"><Check className="w-3 h-3" /></button>
        <button type="button" onClick={() => setEditing(false)} className="text-muted-foreground hover:text-foreground"><X className="w-3 h-3" /></button>
      </span>
    );
  }

  if (tag) {
    return (
      <span className={`inline-flex items-center gap-1 group ${className}`}>
        <span className="font-mono font-bold" title={ip}>{ip}</span>
        <span
          className="text-[10px] px-1.5 py-0.5 rounded-full font-medium cursor-pointer hover:opacity-80"
          style={{ backgroundColor: (tag.color || '#3b82f6') + '20', color: tag.color || '#3b82f6', border: `1px solid ${(tag.color || '#3b82f6')}30` }}
          onClick={() => { setTagName(tag.name); setEditing(true); }}
          title={`Click to edit — ${ip}`}
        >
          {tag.name}
        </span>
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); removeAssetTag(ip); forceUpdate(n => n + 1); }}
          className="hidden group-hover:inline text-muted-foreground hover:text-destructive"
          title="Remove tag"
        ><X className="w-2.5 h-2.5" /></button>
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center gap-1 group ${className}`}>
      <span className="font-mono font-bold">{ip}</span>
      <button
        type="button"
        onClick={() => { setTagName(''); setEditing(true); }}
        className="hidden group-hover:inline text-muted-foreground hover:text-primary"
        title="Tag this IP"
      >
        <Tag className="w-2.5 h-2.5" />
      </button>
    </span>
  );
}
