import assert from "node:assert/strict"
import { test } from "node:test"

import createFetchClient from "openapi-fetch"

import {
  accessTokenExpiry,
  BauthError,
  createAuthMiddleware,
  createBauthClient,
  createSession
} from "../dist/index.js"

const json = (status, body) =>
  new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" }
  })

/** Answers with `route(request)`, and records every request (with its body read). */
function routedFetch(route) {
  const requests = []
  const fetch = async request => {
    const body = await request.clone().text()
    requests.push({ url: request.url, method: request.method, headers: request.headers, body })
    return route(request, body)
  }
  return { fetch, requests }
}

const options = { baseUrl: "https://auth.test", clientId: "my-app", redirectUri: "https://app.test/cb" }

/** A store kept in memory, like `localStorage` or a cookie would. */
function memoryStore(initial) {
  let value = initial
  return { read: () => value, write: next => void (value = next), get: () => value }
}

/** An unsigned token whose `exp` is `inSeconds` from now: enough for `accessTokenExpiry`. */
function jwt(inSeconds) {
  const b64 = value => Buffer.from(JSON.stringify(value)).toString("base64url")
  return `${b64({ alg: "EdDSA" })}.${b64({ exp: Math.floor(Date.now() / 1000) + inSeconds })}.sig`
}

const tokens = (access, refresh = "r2", expires_in = 900) => ({
  access_token: access,
  refresh_token: refresh,
  token_type: "Bearer",
  expires_in
})

test("createBauthClient refuses missing settings", () => {
  for (const missing of ["baseUrl", "clientId", "redirectUri"]) {
    assert.throws(() => createBauthClient({ ...options, [missing]: "" }), new RegExp(missing))
    assert.throws(() => createBauthClient({ ...options, [missing]: undefined }), new RegExp(missing))
  }
})

test("requestMagicCode continues the flow of the same address, and restarts an exhausted one", async () => {
  let flows = 0
  let emailsOnFlow = 0
  const { fetch, requests } = routedFetch(request => {
    if (request.url.endsWith("/flows/login")) {
      flows++
      emailsOnFlow = 0
      return json(201, { flow_id: `f${flows}`, methods: ["magic_link"], expires_at: "2999-01-01T00:00:00Z" })
    }
    emailsOnFlow++
    if (emailsOnFlow > 3) return json(429, { code: "rate_limited", message: "" })
    // Each email pushes the flow's expiry further.
    return json(202, { status: "magic_link_sent", expires_at: `2999-01-0${emailsOnFlow}T00:15:00Z` })
  })
  const bauth = createBauthClient({ ...options, fetch })
  const store = memoryStore()

  await bauth.requestMagicCode("a@b.c", store)
  await bauth.requestMagicCode("a@b.c", store)
  await bauth.requestMagicCode("a@b.c", store)
  assert.equal(flows, 1, "same address, same flow")
  assert.equal(store.get().flowId, "f1")
  assert.equal(store.get().expiresAt, "2999-01-03T00:15:00Z", "the flow's latest expiry is kept")

  await bauth.requestMagicCode("a@b.c", store) // 4th email: refused on f1, sent on a new flow
  assert.equal(store.get().flowId, "f2")
  assert.equal(requests.filter(r => r.url.endsWith("/magic-link")).length, 5)

  await bauth.requestMagicCode("other@b.c", store)
  assert.deepEqual([store.get().flowId, store.get().email], ["f3", "other@b.c"])
})

test("requestMagicCode keeps the flow on other errors", async () => {
  const { fetch } = routedFetch(() => json(400, { code: "invalid_email", message: "" }))
  const pending = { flowId: "f1", codeVerifier: "v", email: "a@b.c", expiresAt: "2999-01-01T00:00:00Z" }
  const store = memoryStore(pending)
  const error = await createBauthClient({ ...options, fetch }).requestMagicCode("a@b.c", store).catch(e => e)
  assert.equal(error.code, "invalid_email")
  assert.equal(store.get(), pending)
})

test("submitMagicCode exchanges the code of the stored flow, then forgets it", async () => {
  const { fetch, requests } = routedFetch(request =>
    request.url.endsWith("/magic-code") ? json(200, { status: "completed", code: "c1" }) : json(200, tokens("a1", "r1"))
  )
  const bauth = createBauthClient({ ...options, fetch })
  const store = memoryStore({ flowId: "f1", codeVerifier: "v1", email: "a@b.c", expiresAt: "2999-01-01T00:00:00Z" })

  assert.equal((await bauth.submitMagicCode("042 917", store)).access_token, "a1")
  assert.deepEqual(JSON.parse(requests[0].body), { code: "042917" })
  assert.match(requests[1].body, /code=c1&redirect_uri=.*&code_verifier=v1/)
  assert.equal(store.get(), undefined)

  const none = await bauth.submitMagicCode("042917", store).catch(e => e)
  assert.ok(none instanceof BauthError)
  assert.equal(none.code, "flow_expired")
})

test("accessTokenExpiry reads exp without verifying", () => {
  const expiry = accessTokenExpiry(jwt(60))
  assert.ok(expiry > Date.now() + 50_000 && expiry <= Date.now() + 60_000)
  assert.equal(accessTokenExpiry("not a token"), undefined)
})

test("a session refreshes once for concurrent callers, and only invalid_grant ends it", async () => {
  let refreshes = 0
  let answer = () => json(200, tokens(jwt(900), `r${refreshes}`))
  const { fetch } = routedFetch(() => {
    refreshes++
    return answer()
  })
  const store = memoryStore({ accessToken: jwt(10), refreshToken: "r0" }) // expires within the margin
  const session = createSession({ bauth: createBauthClient({ ...options, fetch }), store })

  const [a, b, c] = await Promise.all([session.accessToken(), session.accessToken(), session.accessToken()])
  assert.equal(refreshes, 1, "one rotation for three callers")
  assert.ok(a && a === b && b === c)
  assert.equal(await session.accessToken(), a, "fresh token: no refresh")
  assert.equal(refreshes, 1)

  // bauth down: the session stays, and the current token is still sent until it expires.
  answer = () => json(503, { code: "internal_error", message: "" })
  store.write({ accessToken: jwt(10), refreshToken: "r1" })
  const kept = store.get()
  assert.equal(await session.accessToken(), kept.accessToken)
  assert.equal(store.get(), kept)

  // Revoked or reused refresh token: the session is over.
  answer = () => json(400, { error: "invalid_grant", error_description: "" })
  assert.equal(await session.refresh(), undefined)
  assert.equal(store.get(), undefined)
  assert.equal(await session.accessToken(), undefined)
})

test("logout clears the store and revokes the session", async () => {
  const { fetch, requests } = routedFetch(() => new Response(null, { status: 200 }))
  const store = memoryStore({ accessToken: jwt(900), refreshToken: "r1" })
  await createSession({ bauth: createBauthClient({ ...options, fetch }), store }).logout()
  assert.equal(store.get(), undefined)
  assert.equal(requests[0].url, "https://auth.test/oauth/revoke")
  assert.match(requests[0].body, /token=r1/)
})

test("the middleware refreshes once after concurrent 401s and replays each request with its body", async () => {
  let current = "stale"
  let refreshes = 0
  let unauthorized = 0
  const sent = []
  // The API only accepts the token "new".
  const { fetch } = routedFetch((request, body) => {
    const auth = request.headers.get("authorization")
    sent.push([auth, body])
    return auth === "Bearer new" ? json(200, { ok: true }) : json(401, {})
  })
  const api = createFetchClient({ baseUrl: "https://api.test", fetch })
  api.use(
    createAuthMiddleware({
      getAccessToken: () => current,
      refreshAccessToken: async () => {
        refreshes++
        await new Promise(resolve => setTimeout(resolve, 10))
        current = "new"
        return current
      },
      onUnauthorized: () => unauthorized++
    })
  )

  const results = await Promise.all([api.POST("/items", { body: { n: 1 } }), api.POST("/items", { body: { n: 2 } })])
  assert.deepEqual(
    results.map(r => r.response.status),
    [200, 200]
  )
  assert.equal(refreshes, 1, "one refresh for both 401s")
  const replayed = sent.filter(([auth]) => auth === "Bearer new").map(([, body]) => JSON.parse(body).n)
  assert.deepEqual(replayed.sort(), [1, 2], "each body sent again")
  assert.equal(unauthorized, 0)
})

test("the middleware reports a session it can't refresh", async () => {
  const { fetch } = routedFetch(() => json(401, {}))
  const api = createFetchClient({ baseUrl: "https://api.test", fetch })
  let unauthorized = 0
  api.use(
    createAuthMiddleware({
      getAccessToken: () => "old",
      refreshAccessToken: async () => undefined,
      onUnauthorized: () => unauthorized++
    })
  )
  const { response } = await api.GET("/items")
  assert.equal(response.status, 401)
  assert.equal(unauthorized, 1)
})
