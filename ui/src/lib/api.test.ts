import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import axios, { AxiosError, AxiosHeaders, type InternalAxiosRequestConfig } from 'axios'

import { getErrorMessage, signOut, signIn, startSession, loadSession, api } from './api'

// A fake transport: each request is recorded and answered by `reply`.
type Sent = { url?: string; method?: string; headers: Record<string, unknown> }
let sent: Sent[]
let reply: (config: InternalAxiosRequestConfig) => Promise<unknown>
const realAdapter = api.defaults.adapter

function answer(config: InternalAxiosRequestConfig, status: number, data: unknown = {}) {
  const response = { data, status, statusText: String(status), headers: {}, config }
  if (status >= 400) {
    return Promise.reject(new AxiosError(String(status), 'ERR_BAD_REQUEST', config, undefined, response as never))
  }
  return Promise.resolve(response)
}

beforeEach(async () => {
  sent = []
  reply = (c) => answer(c, 200)
  api.defaults.adapter = (config) => {
    sent.push({ url: config.url, method: config.method, headers: AxiosHeaders.from(config.headers).toJSON() })
    return reply(config) as never
  }
  await signOut() // no session left from another test
  sent = []
})
afterEach(() => {
  api.defaults.adapter = realAdapter
  vi.restoreAllMocks()
})

describe('getErrorMessage', () => {
  it('returns fallback for non-axios errors', () => {
    expect(getErrorMessage(new Error('test'), 'fallback')).toBe('fallback')
  })

  it('returns fallback for undefined errors', () => {
    expect(getErrorMessage(undefined, 'oops')).toBe('oops')
  })
})

describe('the session', () => {
  it('signs in asking for a cookie session and keeps nothing in localStorage', async () => {
    reply = (c) => answer(c, 200, { status: 'success', username: 'admin', expires_at: Math.floor(Date.now() / 1000) + 3600 })
    await signIn('admin', 'pw-123456!')
    expect(sent[0]).toMatchObject({ url: 'auth/login', method: 'post' })
    expect(sent[0].headers['X-SPM-Session']).toBe('cookie')
    expect(localStorage.length).toBe(0)
  })

  it('sends X-Requested-With: spm on every request, the header the backend checks against CSRF', async () => {
    await api.get('status')
    await api.post('settings', {})
    expect(sent.map((s) => s.headers['X-Requested-With'])).toEqual(['spm', 'spm'])
  })

  it('reads the session from GET /api/session: null on 401, thrown when the backend is down', async () => {
    reply = (c) => answer(c, 200, { status: 'success', data: { username: 'admin', via: 'cookie', expires_at: 1900000000 } })
    expect(await loadSession()).toMatchObject({ username: 'admin', via: 'cookie' })
    reply = (c) => answer(c, 401)
    expect(await loadSession()).toBeNull()
    reply = (c) => answer(c, 502)
    await expect(loadSession()).rejects.toBeInstanceOf(AxiosError)
  })

  it('signs out through the backend, which revokes the token and clears the cookie', async () => {
    startSession(null)
    await signOut()
    expect(sent.map((s) => s.url)).toEqual(['logout'])
    sent = []
    await signOut() // no session: nothing to revoke
    expect(sent).toEqual([])
  })

  it('still signs out locally when the server call fails', async () => {
    startSession(null)
    reply = (c) => answer(c, 500)
    await signOut()
    sent = []
    reply = (c) => answer(c, 200)
    await signOut()
    expect(sent).toEqual([]) // the session ended despite the failure
  })

  it('announces the end of the session once on a 401, not on a failed sign-in', async () => {
    const ended = vi.fn()
    window.addEventListener('session-ended', ended)
    try {
      startSession(null)
      reply = (c) => answer(c, 401)
      await expect(api.post('auth/login', {})).rejects.toBeTruthy()
      expect(ended).not.toHaveBeenCalled()
      await expect(api.get('status')).rejects.toBeTruthy()
      await expect(api.get('health')).rejects.toBeTruthy()
      expect(ended).toHaveBeenCalledTimes(1)
    } finally {
      window.removeEventListener('session-ended', ended)
    }
  })

  it('warns five minutes before the session expires, and ends it at the expiry', async () => {
    const expiring = vi.fn()
    const ended = vi.fn()
    window.addEventListener('session-expiring', expiring)
    window.addEventListener('session-ended', ended)
    try {
      startSession(Math.floor(Date.now() / 1000) + 4 * 60)
      await api.get('status')
      await api.get('status')
      expect(expiring).toHaveBeenCalledTimes(1)
      expect(ended).not.toHaveBeenCalled()
      startSession(Math.floor(Date.now() / 1000) - 1)
      await api.get('status')
      expect(ended).toHaveBeenCalledTimes(1)
    } finally {
      window.removeEventListener('session-expiring', expiring)
      window.removeEventListener('session-ended', ended)
    }
  })
})

describe('a token left in localStorage by an earlier version', () => {
  it('is revoked with the backend once and removed', async () => {
    const calls: Sent[] = []
    const old = axios.defaults.adapter
    axios.defaults.adapter = (config) => {
      calls.push({ url: config.url, method: config.method, headers: AxiosHeaders.from(config.headers).toJSON() })
      return answer(config, 200) as never
    }
    localStorage.setItem('auth_token', 'old.jwt.token')
    try {
      vi.resetModules()
      await import('./api')
      await vi.waitFor(() => expect(calls).toHaveLength(1))
      expect(calls[0]).toMatchObject({ url: 'logout', method: 'post' })
      expect(calls[0].headers.Authorization).toBe('Bearer old.jwt.token')
      expect(localStorage.getItem('auth_token')).toBeNull()
    } finally {
      axios.defaults.adapter = old
      localStorage.clear()
    }
  })
})
