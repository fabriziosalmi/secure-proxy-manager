// The one way the UI writes a count. toLocaleString() follows the browser
// locale, so the same page showed "1328" in one place and "50.772" in another
// (an Italian browser groups with a dot, raw numbers are not grouped at all).
// A fixed locale gives 1,328 and 50,772 everywhere, whoever opens the page.
const COUNT = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });

/** A whole-number count with en-US grouping: 1328 -> "1,328". */
export function formatCount(n: number): string {
  return COUNT.format(n);
}
