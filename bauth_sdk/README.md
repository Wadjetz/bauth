# @wadjetz/bauth-client

Framework-agnostic client for [bauth](https://github.com/Wadjetz/bauth), a headless authentication
server: your app draws the screens, this package calls bauth's API. Typed from bauth's OpenAPI spec.
Works wherever `fetch` and Web Crypto exist: browsers, Node 20+, SvelteKit, Tauri.

> [!WARNING]
> **bauth is written with AI assistance and its human review is still in progress.** It has not been
> audited. Use it at your own risk: no warranty of any kind (MIT license).

```sh
npm install @wadjetz/bauth-client
```

The package version follows the SDK, not the server: use the SDK released alongside your bauth server
(its types are generated from that server's `openapi.json`).

## Usage

```ts
import {
  createBauthClient,
  createSession,
  isBauthError,
  keyValueStore,
  localStorageStore,
  type PendingMagicCode,
  type StoredTokens
} from "@wadjetz/bauth-client"

const bauth = createBauthClient({
  baseUrl: "https://auth.example.com",
  clientId: "my-app",
  redirectUri: "https://app.example.com/auth/callback"
})
```

### Login and sign-up: magic link and 6-digit code

bauth has no passwords: users log in with an email that carries both a link and a code. The code is
typed on the screen that asked for the email (mobile mail apps often open links in another browser);
the link works when opened on the same device. It is also the sign-up: for an unknown address (and a
client with `allow_signup`), the account is created, email verified, when the code or link is used.

```ts
// Where the login in progress lives between the two screens, and until the link comes back.
const flows = localStorageStore<PendingMagicCode>("bauth_flow")

// Asking again for the same address continues the flow; a new one starts after 3 emails.
await bauth.requestMagicCode(email, flows)
// Same screen: the code from the email ("042 917" is fine).
const tokens = await bauth.submitMagicCode(digits, flows)
```

```ts
// Page the link opens (the link opens a new tab: that is why the flow is in localStorage)
try {
  const tokens = await bauth.submitMagicLink(location.href, flows)
} catch (error) {
  if (isBauthError(error, "flow_expired")) {
    // Another browser or device: the link was left unused, since confirming it would also disable
    // the code. Ask the user to type the code where they started.
  }
}
```

`startLogin`, `requestMagicLink`, `confirmMagicLink`, `confirmMagicCode` and `exchangeCode` are the
steps underneath, for a flow of your own.

### Session

`createSession` keeps the tokens in a store of yours and knows bauth's rules: refresh ahead of
expiry, one refresh for concurrent callers (replaying a rotated refresh token revokes the session),
and only `invalid_grant` ends the session — offline or bauth down keeps it.

```ts
const session = createSession({ bauth, store: localStorageStore("bauth_tokens") })
await session.save(tokens)

// Your API client (openapi-fetch): bearer token, refresh, one replay after a 401.
api.use(session.middleware({ onUnauthorized: () => goto("/login") }))
// Or a plain fetch doing the same.
const apiFetch = session.fetcher({ onUnauthorized: () => goto("/login") })
await apiFetch("https://api.example.com/items")
```

Stores: `localStorageStore(key)` (shared by the tabs; readable by any script of the page, so prefer
`httpOnly` cookies when a server is in front), `memoryStore()` (gone on reload), and
`keyValueStore(key, storage)` over any string key/value storage, sync or async. In Tauri, the
tokens belong in the OS keychain (a keychain or Stronghold plugin) rather than in the webview's
`localStorage`; any storage with `get` / `set` / `delete` fits, e.g. `@tauri-apps/plugin-store`
(not encrypted):

```ts
import { load } from "@tauri-apps/plugin-store"

const store = keyValueStore<StoredTokens>("tokens", await load("auth.json"))
```

On a server keeping tokens in `httpOnly` cookies, the store reads and writes the cookies of the
request (`expiresAt` may be left out: it is read from the token), and `session.accessToken()` gives
the token to forward. `createAuthMiddleware` is the middleware alone, for your own token handling.

### Errors

Every failure is a `BauthError` with a stable `code` to translate (`invalid_code`, `flow_expired`,
`rate_limited` with `retryAfter`…), typed as `BauthErrorCode`; `isBauthError(error, ...codes)`
narrows on them. bauth unreachable (offline, DNS, CORS) is `network_error`; an abort is rethrown as
is. The codes of each route are listed in bauth's
[`openapi.json`](https://github.com/Wadjetz/bauth/blob/main/bauth_server/openapi.json).
Anything not wrapped is reachable through the typed `bauth.api` (openapi-fetch) client.

## Development

```sh
npm install
npm run generate   # after bauth_server/openapi.json changes
npm test           # builds, then runs test/*.test.js
```

Releasing: published by hand with `npm publish`, see [Releasing the SDK](https://github.com/Wadjetz/bauth#releasing-the-sdk).
