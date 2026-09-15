function base64url(bytes: Uint8Array): string {
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

/** A random PKCE `code_verifier` (32 bytes, 43 characters). Keep it secret until the code exchange. */
export function generateCodeVerifier(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return base64url(bytes)
}

/** `code_challenge` for `code_challenge_method=S256`: base64url(SHA-256(verifier)). */
export async function computeCodeChallenge(codeVerifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier))
  return base64url(new Uint8Array(digest))
}
