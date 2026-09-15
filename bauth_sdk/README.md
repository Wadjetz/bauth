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
import { BauthError, createBauthClient, tokenFromUrl } from "@wadjetz/bauth-client"

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

```ts
const flow = await bauth.startLogin()
// The link opens in a new tab: keep the flow in localStorage (sessionStorage is per tab).
localStorage.setItem("bauth_flow", JSON.stringify({ flowId: flow.flowId, codeVerifier: flow.codeVerifier }))
await bauth.requestMagicLink(flow.flowId, email)

// Same screen: the code from the email
const code = await bauth.confirmMagicCode(flow.flowId, digits)
const tokens = await bauth.exchangeCode(code, flow.codeVerifier)
```

```ts
// Page the link opens
const saved = localStorage.getItem("bauth_flow")
if (saved) {
  const { codeVerifier } = JSON.parse(saved)
  const code = await bauth.confirmMagicLink(tokenFromUrl(location.href)!)
  const tokens = await bauth.exchangeCode(code, codeVerifier)
} else {
  // Another browser or device: don't confirm the link, it would also disable the code.
  // Ask the user to type the code where they started.
}
```

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
