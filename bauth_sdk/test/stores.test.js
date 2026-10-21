import assert from "node:assert/strict"
import { test } from "node:test"

import { keyValueStore, localStorageStore, memoryStore } from "../dist/index.js"

/** The `Storage` interface over a Map, like the browser's `localStorage`. */
function fakeStorage() {
  const items = new Map()
  return {
    items,
    getItem: key => items.get(key) ?? null,
    setItem: (key, value) => void items.set(key, String(value)),
    removeItem: key => void items.delete(key)
  }
}

test("memoryStore keeps the value until forgotten", async () => {
  const store = memoryStore({ a: 1 })
  assert.deepEqual(await store.read(), { a: 1 })
  await store.write(undefined)
  assert.equal(await store.read(), undefined)
})

test("localStorageStore keeps JSON under its key and forgets with undefined", async () => {
  const storage = fakeStorage()
  const store = localStorageStore("bauth_tokens", storage)
  assert.equal(await store.read(), undefined)

  await store.write({ accessToken: "a", refreshToken: "r" })
  assert.equal(storage.items.get("bauth_tokens"), '{"accessToken":"a","refreshToken":"r"}')
  assert.deepEqual(await store.read(), { accessToken: "a", refreshToken: "r" })

  await store.write(undefined)
  assert.equal(storage.items.has("bauth_tokens"), false)
})

test("a value that doesn't parse reads as missing", async () => {
  const storage = fakeStorage()
  storage.setItem("k", "{not json")
  assert.equal(await localStorageStore("k", storage).read(), undefined)
  storage.setItem("k", "null")
  assert.equal(await localStorageStore("k", storage).read(), undefined)
})

test("keyValueStore works over an async storage (Tauri plugin-store, keychain…)", async () => {
  const items = new Map()
  const storage = {
    get: async key => items.get(key), // undefined when missing, like plugin-store
    set: async (key, value) => void items.set(key, value),
    delete: async key => items.delete(key)
  }
  const store = keyValueStore("flow", storage)
  assert.equal(await store.read(), undefined)
  await store.write({ flowId: "f1" })
  assert.deepEqual(await store.read(), { flowId: "f1" })
  await store.write(undefined)
  assert.equal(items.size, 0)
})
