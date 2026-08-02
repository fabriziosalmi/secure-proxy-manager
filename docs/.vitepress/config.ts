import { defineConfig } from 'vitepress'

// Canonical origin (GitHub Pages) including the project base path. Used for
// per-page canonical/og:url links and the sitemap.
const SITE_URL = 'https://fabriziosalmi.github.io/secure-proxy-manager'
const OG_DESCRIPTION =
  'Self-hosted Secure Web Gateway: Squid forward proxy + a real WAF (ICAP) + DNS sinkhole + a modern UI, in one Docker Compose stack.'

export default defineConfig({
  title: 'Secure Proxy Manager',
  description: 'Documentation for Secure Proxy Manager — a containerised Squid forward proxy with a Go backend, React UI, and Go ICAP WAF.',
  base: '/secure-proxy-manager/',
  cleanUrls: true,
  lastUpdated: true,
  srcExclude: ['INTEGRATION_ARCHITECTURE.md'],

  // hostname includes the base path; VitePress joins relative page paths onto it.
  sitemap: { hostname: `${SITE_URL}/` },

  // Per-page canonical + og:url (relative path → clean URL under SITE_URL).
  transformPageData(pageData) {
    const rel = pageData.relativePath
      .replace(/(^|\/)index\.md$/, '$1')
      .replace(/\.md$/, '')
    const canonical = rel ? `${SITE_URL}/${rel}` : `${SITE_URL}/`
    pageData.frontmatter.head ??= []
    pageData.frontmatter.head.push(
      ['link', { rel: 'canonical', href: canonical }],
      ['meta', { property: 'og:url', content: canonical }],
    )
  },

  head: [
    // Social / Open Graph defaults (site-level; per-page og:url is injected in
    // transformPageData). No og:image yet — a 1200×630 raster (M9) will upgrade
    // twitter:card to summary_large_image.
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'Secure Proxy Manager' }],
    ['meta', { property: 'og:title', content: 'Secure Proxy Manager — Self-hosted Secure Web Gateway' }],
    ['meta', { property: 'og:description', content: OG_DESCRIPTION }],
    ['meta', { name: 'twitter:card', content: 'summary' }],
    ['meta', { name: 'twitter:title', content: 'Secure Proxy Manager — Self-hosted Secure Web Gateway' }],
    ['meta', { name: 'twitter:description', content: OG_DESCRIPTION }],
    // Everything this site loads is first-party. 'unsafe-inline' is required
    // because VitePress emits an inline appearance script and inline styles.
    // Applied to the built site only: `vitepress dev` serves HMR over a
    // websocket, which a strict connect-src would block as soon as the dev
    // server is not same-origin (--host, or a custom server.hmr.port).
    ...(process.env.NODE_ENV === 'production'
      ? [
          [
            'meta',
            {
              'http-equiv': 'Content-Security-Policy',
              content:
                "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
                "font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'",
            },
          ] as [string, Record<string, string>],
        ]
      : []),
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/secure-proxy-manager/favicon.svg' }]
  ],

  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'API Reference', link: '/api/reference' },
      { text: 'GitHub', link: 'https://github.com/fabriziosalmi/secure-proxy-manager' }
    ],

    sidebar: [
      {
        text: 'Introduction',
        items: [
          { text: 'What is Secure Proxy Manager?', link: '/guide/introduction' },
          { text: 'Getting Started', link: '/guide/getting-started' },
          { text: 'Architecture', link: '/guide/architecture' }
        ]
      },
      {
        text: 'Configuration',
        items: [
          { text: 'Environment Variables', link: '/guide/configuration' },
          { text: 'Blacklists and Whitelists', link: '/guide/blacklists' },
          { text: 'Security', link: '/guide/security' },
          { text: 'Security Advisories', link: '/guide/security-advisories' }
        ]
      },
      {
        text: 'API Reference',
        items: [
          { text: 'Overview', link: '/api/reference' },
          { text: 'Authentication', link: '/api/authentication' },
          { text: 'Blacklists and Whitelists', link: '/api/blacklists' },
          { text: 'Logs and Analytics', link: '/api/logs' },
          { text: 'Settings and Maintenance', link: '/api/settings' },
          { text: 'WebSocket', link: '/api/websocket' }
        ]
      }
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/fabriziosalmi/secure-proxy-manager' }
    ],

    footer: {
      message: 
        'Released under the MIT License. · <a href="https://fabriziosalmi.github.io/privacy">Privacy &amp; legal</a>',
      copyright: 'Secure Proxy Manager contributors'
    },

    search: {
      provider: 'local'
    }
  }
})
