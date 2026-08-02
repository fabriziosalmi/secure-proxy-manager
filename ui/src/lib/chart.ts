// Shared recharts styling. The tooltip look is identical across every chart
// surface (Dashboard + Threat Intel), so it lives here instead of being
// re-declared per file. Colour palettes stay local — they intentionally differ
// in length/order between surfaces.
export const TOOLTIP_STYLE = {
  backgroundColor: 'var(--tooltip-bg)',
  backdropFilter: 'blur(12px)',
  WebkitBackdropFilter: 'blur(12px)',
  border: '1px solid var(--tooltip-border)',
  borderRadius: '8px',
  fontSize: '11px',
  color: 'hsl(var(--foreground))',
  boxShadow: 'var(--tooltip-shadow)',
  fontVariantNumeric: 'tabular-nums' as const,
};
