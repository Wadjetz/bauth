# @bauth/client

Framework-agnostic client for bauth, built on the generated OpenAPI types (`src/schema.ts`).
Works wherever `fetch` and Web Crypto exist: browsers, Node, SvelteKit, Tauri.

```ts
import { BauthError, createBauthClient, tokenFromUrl } from "@bauth/client"

const bauth = createBauthClient({
  baseUrl: "https://auth.example.com",
  clientId: "my-app",
  redirectUri: "https://app.example.com/auth/callback"
})

// Password login
try {
  const tokens = await bauth.loginWithPassword(email, password)
} catch (error) {
  if (error instanceof BauthError && error.code === "email_not_verified") await bauth.resendVerification(email)
}

// Magic link: keep the PKCE verifier until the link comes back
const flow = await bauth.startLogin()
sessionStorage.setItem("bauth_verifier", flow.codeVerifier)
await bauth.requestMagicLink(flow.flowId, email)
// …on the page the link opens:
const code = await bauth.confirmMagicLink(tokenFromUrl(location.href)!)
const tokens = await bauth.exchangeCode(code, sessionStorage.getItem("bauth_verifier")!)
// …or, on the same screen, with the 6-digit code of the email (e.g. mail read on another device):
const code = await bauth.confirmMagicCode(flow.flowId, digits)
const tokens = await bauth.exchangeCode(code, flow.codeVerifier)
```

Errors are `BauthError` with a stable `code` to translate (listed per route in `openapi.json`).

## Development

```sh
npm install
npm run generate   # after bauth_server/openapi.json changes
npm test           # builds, then runs test/*.test.js
```
