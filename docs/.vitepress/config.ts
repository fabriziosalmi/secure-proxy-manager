import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Secure Proxy Manager',
  description: 'Documentation for Secure Proxy Manager — a containerized Squid-based proxy with FastAPI backend, React UI, and ICAP WAF.',
  base: '/secure-proxy-manager/',

  head: [
    ['link', { rel: 'icon', href: '/secure-proxy-manager/favicon.ico' }]
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
          { text: 'Security Settings', link: '/guide/security' }
        ]
      },
      {
        text: 'API Reference',
        items: [
          { text: 'Authentication', link: '/api/authentication' },
          { text: 'Blacklist & Whitelist', link: '/api/blacklists' },
          { text: 'Logs & Analytics', link: '/api/logs' },
          { text: 'Settings & Maintenance', link: '/api/settings' },
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
