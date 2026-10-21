type MaybePromise<T> = T | Promise<T>

/**
 * Where the SDK keeps a value between page loads: the tokens of a session (`TokenStore`), the
 * login in progress (`FlowStore`). Implement it for any storage, or use the ones below.
 */
export interface Store<T> {
  read(): MaybePromise<T | undefined>
  /** `undefined` forgets the value. */
  write(value: T | undefined): MaybePromise<void>
}

/** Kept in memory only: gone on reload. For tests, SSR requests, or tokens you don't want on disk. */
export function memoryStore<T>(initial?: T): Store<T> {
  let value = initial
  return {
    read: () => value,
    write: next => {
      value = next
    }
  }
}

/**
 * A string key/value storage, possibly async: Tauri's plugin-store, a keychain plugin, a cookie
 * jar… `get` may answer `null` or `undefined` for a missing key.
 */
export interface KeyValueStorage {
  get(key: string): MaybePromise<string | null | undefined>
  set(key: string, value: string): MaybePromise<unknown>
  delete(key: string): MaybePromise<unknown>
}

/**
 * Keeps the value as JSON under `key`. A value that doesn't parse (written by something else,
 * truncated) reads as missing rather than breaking the app.
 */
export function keyValueStore<T>(key: string, storage: KeyValueStorage): Store<T> {
  return {
    async read() {
      const raw = await storage.get(key)
      if (raw == null) return undefined
      try {
        return (JSON.parse(raw) ?? undefined) as T | undefined
      } catch {
        return undefined
      }
    },
    async write(value) {
      if (value === undefined) await storage.delete(key)
      else await storage.set(key, JSON.stringify(value))
    }
  }
}

/**
 * Keeps the value in `localStorage` (or `sessionStorage`) under `key`, shared by the tabs of the
 * origin: a magic link opened in a new tab finds the flow, and every tab sees refreshed tokens.
 * Readable by any script of the page, so an XSS can steal the tokens: prefer `httpOnly` cookies
 * when a server is in front.
 */
export function localStorageStore<T>(key: string, storage?: Storage): Store<T> {
  // Looked up on use, not on creation: during SSR `localStorage` doesn't exist.
  const resolve = () => storage ?? globalThis.localStorage
  return keyValueStore<T>(key, {
    get: name => resolve().getItem(name),
    set: (name, value) => resolve().setItem(name, value),
    delete: name => resolve().removeItem(name)
  })
}
