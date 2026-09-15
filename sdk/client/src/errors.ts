/**
 * An error answered by bauth. `code` is stable (e.g. `invalid_credentials`, `flow_expired`,
 * `rate_limited`): translate it for users. `message` is for developers.
 * For `/oauth/*`, `code` is the RFC 6749 `error` (e.g. `invalid_grant`).
 */
export class BauthError extends Error {
  readonly status: number
  readonly code: string
  /** Seconds to wait, on `rate_limited`. */
  readonly retryAfter: number | undefined

  constructor(status: number, code: string, message: string, retryAfter?: number) {
    super(message)
    this.name = "BauthError"
    this.status = status
    this.code = code
    this.retryAfter = retryAfter
  }

  static async fromResponse(response: Response, body: unknown): Promise<BauthError> {
    const retryAfterHeader = response.headers.get("Retry-After")
    const retryAfter = retryAfterHeader ? Number(retryAfterHeader) : undefined
    if (body && typeof body === "object") {
      const { code, message, error, error_description } = body as Record<string, unknown>
      if (typeof code === "string") {
        return new BauthError(response.status, code, String(message ?? code), retryAfter)
      }
      if (typeof error === "string") {
        return new BauthError(response.status, error, String(error_description ?? error), retryAfter)
      }
    }
    return new BauthError(response.status, "unexpected_response", `HTTP ${response.status}`, retryAfter)
  }
}
