import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Hostname } from './Hostname'

const hostnameEl = (container: HTMLElement, name: string) => container.querySelector(`[data-hostname="${name}"]`) as HTMLElement

describe('Hostname', () => {
  // "gsp57-ssl-background.ls.apple.c" over "om": break-all cut a label in two.
  it('may wrap a name only after a dot, keeps each label and its hyphens on one line, and keeps the name whole', () => {
    const { container } = render(<Hostname name="gsp57-ssl-background.ls.apple.com" />)
    const el = hostnameEl(container, 'gsp57-ssl-background.ls.apple.com')
    expect(el).toHaveTextContent(/^gsp57-ssl-background\.ls\.apple\.com$/)
    const breaks = [...el.querySelectorAll('wbr')]
    expect(breaks).toHaveLength(3)
    for (const wbr of breaks) expect(wbr.previousSibling?.textContent?.endsWith('.')).toBe(true)
    expect([...el.querySelectorAll('span.whitespace-nowrap')].map((s) => s.textContent)).toEqual(['gsp57-ssl-background.', 'ls.', 'apple.', 'com'])
    expect(el).not.toHaveClass('break-all')
    expect(el).not.toHaveClass('truncate')
    expect(el.className).toContain('[overflow-wrap:break-word]')
  })

  it('may also wrap a URL after a slash, but not between the two slashes of its scheme', () => {
    const url = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
    const { container } = render(<Hostname name={url} />)
    expect(hostnameEl(container, url).textContent).toBe(url)
    const before = [...container.querySelectorAll('wbr')].map((w) => w.previousSibling?.textContent?.slice(-1))
    expect(before.length).toBeGreaterThan(0)
    expect(before.every((c) => c === '.' || c === '/')).toBe(true)
    expect(container.innerHTML).not.toMatch(/\/<\/span><wbr><span class="whitespace-nowrap">\//)
  })

  // A label longer than any column (a 36-character id) must not run out of its box.
  it('lets a label too long for any column break as a last resort', () => {
    const name = '3f2b8c1e-9a7d-4c6e-b5f0-123456789abc.cdn.example'
    const { container } = render(<Hostname name={name} />)
    const nowrap = [...hostnameEl(container, name).querySelectorAll('span.whitespace-nowrap')].map((s) => s.textContent)
    expect(nowrap).toEqual(['cdn.', 'example'])
  })

  it('cuts a name to one line with the whole name in its title when asked to truncate', () => {
    const { container } = render(<Hostname name="clientservices.googleapis.com:443" truncate />)
    const el = screen.getByTitle('clientservices.googleapis.com:443')
    expect(el).toHaveClass('truncate')
    expect(el).toHaveTextContent('clientservices.googleapis.com:443')
    expect(container.querySelectorAll('wbr')).toHaveLength(0)
  })
})
