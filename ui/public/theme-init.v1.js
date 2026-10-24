// Applies the saved theme before the app paints, so the page does not flash
// the wrong one. It is a file and not an inline <script> because the CSP is
// script-src 'self': the inline copy was blocked and never ran.
// Unhashed and cached for a year as immutable by nginx: change the file name
// (v2, v3, ...) together with index.html when changing its content.
(function () {
  try {
    var theme = localStorage.getItem('theme') || 'auto';
    var isDark = theme === 'dark' || (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.classList.toggle('dark', isDark);
    document.documentElement.style.colorScheme = isDark ? 'dark' : 'light';
  } catch (_) {
    /* no storage: the app applies the theme itself */
  }
})();
