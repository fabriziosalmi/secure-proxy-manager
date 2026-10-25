# A tour of the dashboard

Thirty seconds through the pages: the Overview, the access log filtered to the
blocked requests with the rule behind one of them, a client's detail,
Blacklists and Analytics.

<video controls muted playsinline preload="metadata" width="1440" poster="/demo/tour-poster.jpg" style="width: 100%; height: auto; border-radius: 8px; border: 1px solid var(--vp-c-divider);">
  <source src="/demo/tour.mp4" type="video/mp4">
  Your browser does not play this video. <a href="/secure-proxy-manager/demo/tour.mp4">Download it</a> (MP4).
</video>

The data is synthetic: a fresh stack, three client containers on a separate
network browsing through the proxy, a few blacklist entries, and requests the
WAF blocks. `scripts/demo/media.sh` regenerates this video and the README
screenshot from the current code.
