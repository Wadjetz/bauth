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
import { BauthError, createBauthClient, createSession, type FlowStore, tokenFromUrl } from "@wadjetz/bauth-client"

const bauth = createBauthClient({
  baseUrl: "https://auth.example.com",
  clientId: "my-app",
  redirectUri: "https://app.example.com/auth/callback"
})
```

### Password

```ts
try {
  const tokens = await bauth.loginWithPassword(email, password)
} catch (error) {
  if (error instanceof BauthError && error.code === "email_not_verified") await bauth.resendVerification(email)
}
```

### Magic link and 6-digit code

One email carries both a link and a code. The code is typed on the screen that asked for the email
(mobile mail apps often open links in another browser); the link works when opened on the same device.
It is also the passwordless sign-up: for an unknown address (and a client with `allow_signup`), the
account is created, email verified, when the code or link is used. No second email.

```ts
// Where the login in progress lives between the two screens (localStorage, a cookie…).
const flows: FlowStore = {
  read: () => JSON.parse(localStorage.getItem("bauth_flow") ?? "null") ?? undefined,
  write: flow => (flow ? localStorage.setItem("bauth_flow", JSON.stringify(flow)) : localStorage.removeItem("bauth_flow"))
}

// Asking again for the same address continues the flow; a new one starts after 3 emails.
await bauth.requestMagicCode(email, flows)
// Same screen: the code from the email ("042 917" is fine).
const tokens = await bauth.submitMagicCode(digits, flows)
```

```ts
// Page the link opens (the link opens a new tab: that is why the flow is in localStorage)
const saved = await flows.read()
if (saved) {
  const { codeVerifier } = saved
  const code = await bauth.confirmMagicLink(tokenFromUrl(location.href)!)
  const tokens = await bauth.exchangeCode(code, codeVerifier)
} else {
  // Another browser or device: don't confirm the link, it would also disable the code.
  // Ask the user to type the code where they started.
}
```

### Session

`createSession` keeps the tokens in a store of yours and knows bauth's rules: refresh ahead of
expiry, one refresh for concurrent callers (replaying a rotated refresh token revokes the session),
and only `invalid_grant` ends the session — offline or bauth down keeps it.

```ts
const session = createSession({
  bauth,
  store: {
    read: () => JSON.parse(localStorage.getItem("bauth_tokens") ?? "null") ?? undefined,
    write: tokens => (tokens ? localStorage.setItem("bauth_tokens", JSON.stringify(tokens)) : localStorage.removeItem("bauth_tokens"))
  }
})
await session.save(tokens)

// Your API client (openapi-fetch): bearer token, refresh, one replay after a 401.
api.use(session.middleware({ onUnauthorized: () => goto("/login") }))
```

On a server keeping tokens in `httpOnly` cookies, the store reads and writes the cookies of the
request (`expiresAt` may be left out: it is read from the token), and `session.accessToken()` gives
the token to forward. `createAuthMiddleware` is the middleware alone, for your own token handling.

### Errors

Every failure is a `BauthError` with a stable `code` to translate (`invalid_credentials`,
`invalid_code`, `flow_expired`, `rate_limited` with `retryAfter`…). The codes of each route are listed
in bauth's [`openapi.json`](https://github.com/Wadjetz/bauth/blob/master/bauth_server/openapi.json).
Anything not wrapped is reachable through the typed `bauth.api` (openapi-fetch) client.

## Development

```sh
npm install
npm run generate   # after bauth_server/openapi.json changes
npm test           # builds, then runs test/*.test.js
```

Releasing: bump `version` in `package.json`, then publish a GitHub release tagged `sdk-v<version>`.
