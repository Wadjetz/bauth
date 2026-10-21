import type { Middleware } from "openapi-fetch"

import type { BauthClient, Tokens } from "./client.js"
import { BauthError } from "./errors.js"
import { createAuthMiddleware } from "./middleware.js"
import type { Store } from "./stores.js"

/** What a session keeps between requests. */
export interface StoredTokens {
  accessToken: string
  refreshToken: string
  /**
   * When the access token stops being accepted, in milliseconds since the epoch. Optional: read
   * from the token's `exp` claim when missing, so a store may keep just the two tokens.
   */
  expiresAt?: number
}

/**
 * Where the tokens live: `localStorageStore`, `memoryStore`, `keyValueStore` over a Tauri store
 * or keychain, `httpOnly` cookies… Writing `undefined` ends the session: forget the tokens.
 */
export type TokenStore = Store<StoredTokens>

export interface FetcherOptions {
  /** Called when a request stays unauthorized after a refresh attempt (logout, redirect…). */
  onUnauthorized?: () => void
  /** The fetch to wrap (Tauri's plugin-http, SvelteKit's `event.fetch`…). Defaults to `globalThis.fetch`. */
  fetch?: typeof globalThis.fetch
}

export interface SessionOptions {
  bauth: BauthClient
  store: TokenStore
  /** Refresh this long before the access token expires, so a request can't be rejected mid-way. */
  expiryMarginMs?: number
}

export interface AuthSession {
  /** Stores the tokens of a login (`submitMagicCode`, `exchangeCode`). */
  save(tokens: Tokens): Promise<void>
  /**
   * The access token to send, refreshed first when it is about to expire. `undefined` when
   * logged out or when the session is over. A refresh that fails for another reason (offline,
   * bauth down) keeps the session and returns the current token if it hasn't expired yet.
   */
  accessToken(): Promise<string | undefined>
  /**
   * Trades the refresh token for new tokens. Concurrent calls share one request: bauth rotates
   * refresh tokens, and replaying a rotated one ends the session. `invalid_grant` (expired,
   * revoked, reused) clears the store and returns `undefined`; any other error is thrown and the
   * session is kept, since the refresh token may well still be good.
   */
  refresh(): Promise<string | undefined>
  /** Clears the store, then revokes the session on bauth (best effort). */
  logout(): Promise<void>
  /** An openapi-fetch middleware for your APIs, backed by this session. */
  middleware(options?: { onUnauthorized?: () => void }): Middleware
  /**
   * A `fetch` for your APIs, backed by this session, when you don't use openapi-fetch: adds the
   * bearer token (refreshed ahead of expiry) and replays a request once after a 401. Without a
   * session the request goes out without `Authorization`.
   */
  fetcher(options?: FetcherOptions): typeof globalThis.fetch
}

const DEFAULT_EXPIRY_MARGIN_MS = 30_000

export function createSession({
  bauth,
  store,
  expiryMarginMs = DEFAULT_EXPIRY_MARGIN_MS
}: SessionOptions): AuthSession {
  let refreshing: Promise<string | undefined> | undefined

  const expiryOf = (tokens: StoredTokens) => tokens.expiresAt ?? accessTokenExpiry(tokens.accessToken)
  const isExpiring = (tokens: StoredTokens, margin = expiryMarginMs) =>
    (expiryOf(tokens) ?? 0) - Date.now() < margin

  async function refresh(): Promise<string | undefined> {
    refreshing ??= (async () => {
      const stored = await store.read()
      if (!stored) return undefined
      try {
        const tokens = await bauth.refresh(stored.refreshToken)
        await store.write(toStored(tokens))
        return tokens.access_token
      } catch (error) {
        if (error instanceof BauthError && error.code === "invalid_grant") {
          await store.write(undefined)
          return undefined
        }
        throw error
      }
    })().finally(() => {
      refreshing = undefined
    })
    return refreshing
  }

  async function accessToken(): Promise<string | undefined> {
    const stored = await store.read()
    if (!stored) return undefined
    if (!isExpiring(stored)) return stored.accessToken
    try {
      return await refresh()
    } catch {
      // Transient failure: the current token is still worth sending until it really expires.
      return isExpiring(stored, 0) ? undefined : stored.accessToken
    }
  }

  return {
    save: tokens => Promise.resolve(store.write(toStored(tokens))),
    accessToken,
    refresh,
    async logout() {
      const stored = await store.read()
      await store.write(undefined)
      if (stored) await bauth.logout(stored.refreshToken).catch(() => undefined)
    },
    middleware: options =>
      createAuthMiddleware({
        getAccessToken: async () => (await store.read())?.accessToken,
        isAccessTokenExpiring: async () => {
          const stored = await store.read()
          return !!stored && isExpiring(stored)
        },
        refreshAccessToken: refresh,
        onUnauthorized: options?.onUnauthorized
      }),
    fetcher: (options = {}) =>
      async (input, init) => {
        const send = options.fetch ?? globalThis.fetch
        const request = new Request(input, init)
        const sent = await accessToken()
        if (!sent) return send(request)

        // Request bodies can be read once: keep a copy for the replay.
        const replay = request.clone()
        request.headers.set("Authorization", `Bearer ${sent}`)
        const response = await send(request)
        if (response.status !== 401) return response

        // Another request may have refreshed meanwhile: use its token rather than rotate again.
        const latest = (await store.read())?.accessToken
        let next: string | undefined
        try {
          next = latest && latest !== sent ? latest : await refresh()
        } catch {
          // bauth unreachable: the session may still be good, don't log the user out.
          return response
        }
        if (!next) {
          options.onUnauthorized?.()
          return response
        }
        replay.headers.set("Authorization", `Bearer ${next}`)
        const retried = await send(replay)
        if (retried.status === 401) options.onUnauthorized?.()
        return retried
      }
  }
}

function toStored(tokens: Tokens): StoredTokens {
  return {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    expiresAt: Date.now() + tokens.expires_in * 1000
  }
}

/**
 * The `exp` claim of an access token, in milliseconds, **without verifying anything**: only to
 * decide when to refresh. APIs verify tokens with `bauth_client`.
 */
export function accessTokenExpiry(accessToken: string): number | undefined {
  const payload = accessToken.split(".")[1]
  if (!payload) return undefined
  try {
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/")
    const claims = JSON.parse(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "=")))
    return typeof claims?.exp === "number" ? claims.exp * 1000 : undefined
  } catch {
    return undefined
  }
}
