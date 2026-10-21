/**
 * The codes bauth answers, and the SDK's own. Which route answers which is listed in bauth's
 * `openapi.json`. A newer server may answer a code missing here: `BauthError.code` stays open to
 * any string, so keep a default branch.
 */
export type BauthErrorCode =
  // App routes (`ErrorBody`)
  | "invalid_request"
  | "invalid_email"
  | "invalid_token"
  | "invalid_code"
  | "invalid_client"
  | "invalid_redirect_uri"
  | "invalid_code_challenge"
  | "account_disabled"
  | "flow_expired"
  | "unauthorized"
  | "not_found"
  | "email_taken"
  | "rate_limited"
  | "internal_error"
  // `/oauth/*` (RFC 6749 `error`)
  | "invalid_grant"
  | "unsupported_grant_type"
  | "server_error"
  // SDK: bauth unreachable (offline, DNS, CORS), or an answer that isn't bauth's (proxy error page)
  | "network_error"
  | "unexpected_response"

/**
 * An error answered by bauth. `code` is stable (e.g. `invalid_code`, `flow_expired`,
 * `rate_limited`): translate it for users. `message` is for developers.
 * For `/oauth/*`, `code` is the RFC 6749 `error` (e.g. `invalid_grant`).
 */
export class BauthError extends Error {
  /** HTTP status; 0 for `network_error`. */
  readonly status: number
  readonly code: BauthErrorCode | (string & {})
  /** Seconds to wait, on `rate_limited`. */
  readonly retryAfter: number | undefined

  constructor(
    status: number,
    code: BauthErrorCode | (string & {}),
    message: string,
    retryAfter?: number,
    options?: ErrorOptions
  ) {
    super(message, options)
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

/**
 * Whether `error` is a `BauthError`, with one of `codes` when given:
 * `if (isBauthError(error, "invalid_code", "flow_expired")) …`.
 */
export function isBauthError(error: unknown): error is BauthError
export function isBauthError<C extends BauthErrorCode>(
  error: unknown,
  ...codes: [C, ...C[]]
): error is BauthError & { code: C }
export function isBauthError(error: unknown, ...codes: string[]): boolean {
  return error instanceof BauthError && (codes.length === 0 || codes.includes(error.code))
}
