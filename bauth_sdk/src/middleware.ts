import type { Middleware } from "openapi-fetch"

export interface AuthMiddlewareOptions {
  /** Reads the current access token. Called on every request. */
  getAccessToken: () => string | undefined | Promise<string | undefined>
  /**
   * Obtains a fresh access token, or `undefined` when it can't be refreshed. Concurrent calls are
   * collapsed into one, so the implementation doesn't have to guard itself.
   */
  refreshAccessToken?: () => Promise<string | undefined>
  /**
   * Whether the token is about to expire, so it is refreshed *before* the request instead of
   * paying a round-trip for a 401. Leave it out to refresh only after a rejection.
   */
  isAccessTokenExpiring?: (accessToken: string) => boolean | Promise<boolean>
  /** Called when a request stays unauthorized after a refresh attempt (logout, redirect…). */
  onUnauthorized?: () => void
}

/**
 * openapi-fetch middleware for the APIs that accept bauth access tokens: adds the bearer token,
 * refreshes it ahead of expiry, and replays a request once after a 401.
 *
 * `Request` bodies can only be read once, so a request that may be replayed is cloned before it
 * is sent. Clones are kept by request id and dropped as soon as the response comes back.
 */
export function createAuthMiddleware(auth: AuthMiddlewareOptions): Middleware {
  const replayable = new Map<string, Request>()
  let refreshing: Promise<string | undefined> | undefined

  // Collapse the refreshes triggered by requests that failed together.
  const refreshOnce = () => {
    if (!auth.refreshAccessToken) return Promise.resolve(undefined)
    refreshing ??= auth.refreshAccessToken().finally(() => {
      refreshing = undefined
    })
    return refreshing
  }

  return {
    onRequest: async ({ request, id }) => {
      let accessToken = await auth.getAccessToken()

      // Renew a token that is about to expire before spending a request on it. A failure here is
      // not fatal: send the old token and let the 401 path deal with it.
      if (accessToken && (await auth.isAccessTokenExpiring?.(accessToken))) {
        accessToken = (await refreshOnce().catch(() => undefined)) ?? accessToken
      }

      if (accessToken) request.headers.set("Authorization", `Bearer ${accessToken}`)
      if (auth.refreshAccessToken) replayable.set(id, request.clone())
      return request
    },
    onResponse: async ({ response, id, options }) => {
      const request = replayable.get(id)
      replayable.delete(id)
      if (response.status !== 401 || !request) return

      const accessToken = await refreshOnce()
      if (!accessToken) {
        auth.onUnauthorized?.()
        return
      }

      request.headers.set("Authorization", `Bearer ${accessToken}`)
      // The client's own fetch, not the global one, so a custom fetch (SSR, Tauri's HTTP plugin,
      // a test double) also handles the replay.
      const retried = await options.fetch(request)
      if (retried.status === 401) auth.onUnauthorized?.()
      return retried
    },
    onError: ({ id }) => {
      replayable.delete(id)
    }
  }
}
