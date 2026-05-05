import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Secure Proxy Manager',
  description: 'Documentation for Secure Proxy Manager — a containerised Squid forward proxy with a Go backend, React UI, and Go ICAP WAF.',
  base: '/secure-proxy-manager/',
  cleanUrls: true,
  lastUpdated: true,
  srcExclude: ['INTEGRATION_ARCHITECTURE.md'],

  head: [
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
          { text: 'Security', link: '/guide/security' }
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
      message: 'Released under the MIT License.',
      copyright: 'Secure Proxy Manager contributors'
    },

    search: {
      provider: 'local'
    }
  }
})
