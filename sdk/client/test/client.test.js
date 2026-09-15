import assert from "node:assert/strict"
import { test } from "node:test"

import { BauthError, computeCodeChallenge, createBauthClient, generateCodeVerifier, tokenFromUrl } from "../dist/index.js"

/** Records requests and answers with the queued responses. */
function fakeFetch(...responses) {
  const requests = []
  const fetch = async request => {
    requests.push({ url: request.url, method: request.method, headers: request.headers, body: await request.text() })
    return responses.shift()
  }
  return { fetch, requests }
}

const json = (status, body, headers = {}) =>
  new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers }
  })

const options = { baseUrl: "https://auth.test", clientId: "my-app", redirectUri: "https://app.test/cb" }

test("PKCE matches RFC 7636 appendix B", async () => {
  assert.equal(
    await computeCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  )
  assert.match(generateCodeVerifier(), /^[A-Za-z0-9_-]{43}$/)
})

test("startLogin sends an S256 challenge and keeps the verifier", async () => {
  const { fetch, requests } = fakeFetch(
    json(201, { flow_id: "f1", methods: ["password", "magic_link"], expires_at: "2026-01-01T00:00:00Z" })
  )
  const flow = await createBauthClient({ ...options, fetch }).startLogin("xyz")
  const sent = JSON.parse(requests[0].body)
  assert.equal(requests[0].url, "https://auth.test/flows/login")
  assert.equal(sent.code_challenge_method, "S256")
  assert.equal(sent.code_challenge, await computeCodeChallenge(flow.codeVerifier))
  assert.deepEqual([sent.client_id, sent.redirect_uri, sent.state], ["my-app", "https://app.test/cb", "xyz"])
  assert.deepEqual(flow.methods, ["password", "magic_link"])
})

test("token endpoints are form-encoded, without empty fields", async () => {
  const tokens = { access_token: "a", refresh_token: "r", token_type: "Bearer", expires_in: 900 }
  const { fetch, requests } = fakeFetch(json(200, tokens), json(200, tokens))
  const client = createBauthClient({ ...options, fetch })
  assert.deepEqual(await client.exchangeCode("c", "v"), tokens)
  await client.refresh("r")
  assert.equal(requests[0].headers.get("content-type"), "application/x-www-form-urlencoded")
  assert.equal(
    requests[0].body,
    "grant_type=authorization_code&client_id=my-app&code=c&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&code_verifier=v"
  )
  assert.equal(requests[1].body, "grant_type=refresh_token&client_id=my-app&refresh_token=r")
})

test("errors become BauthError with the stable code", async () => {
  const { fetch } = fakeFetch(
    json(400, { code: "invalid_credentials", message: "email or password is incorrect" }),
    json(429, { code: "rate_limited", message: "too many attempts" }, { "Retry-After": "42" }),
    json(400, { error: "invalid_grant", error_description: "code is invalid" })
  )
  const client = createBauthClient({ ...options, fetch })

  const credentials = await client.submitPassword("f1", "a@b.c", "wrong").catch(e => e)
  assert.ok(credentials instanceof BauthError)
  assert.deepEqual([credentials.status, credentials.code], [400, "invalid_credentials"])

  const limited = await client.register("a@b.c", "long enough password").catch(e => e)
  assert.deepEqual([limited.code, limited.retryAfter], ["rate_limited", 42])

  const grant = await client.exchangeCode("c", "v").catch(e => e)
  assert.deepEqual([grant.code, grant.message], ["invalid_grant", "code is invalid"])
})

test("account routes send the bearer token; 204 resolves", async () => {
  const { fetch, requests } = fakeFetch(json(200, { id: "u1", email: "a@b.c" }), new Response(null, { status: 204 }))
  const client = createBauthClient({ ...options, fetch })
  assert.equal((await client.getMe("at")).email, "a@b.c")
  await client.revokeSession("at", "s1")
  assert.equal(requests[0].headers.get("authorization"), "Bearer at")
  assert.deepEqual([requests[1].method, requests[1].url], ["DELETE", "https://auth.test/me/sessions/s1"])
})

test("tokenFromUrl reads the fragment", () => {
  assert.equal(tokenFromUrl("https://app.test/auth/magic-link#token=abc_-1"), "abc_-1")
  assert.equal(tokenFromUrl("https://app.test/auth/magic-link?token=abc"), null)
})

test("confirmMagicCode posts the code on the flow", async () => {
  const { fetch, requests } = fakeFetch(json(200, { status: "completed", code: "c1" }))
  const client = createBauthClient({ ...options, fetch })
  assert.equal(await client.confirmMagicCode("f1", "042917"), "c1")
  assert.equal(requests[0].url, "https://auth.test/flows/login/f1/magic-code")
  assert.deepEqual(JSON.parse(requests[0].body), { code: "042917" })
})
