import createFetchClient from "openapi-fetch";

import { BauthError } from "./errors.js";
import { computeCodeChallenge, generateCodeVerifier } from "./pkce.js";
import type { components, paths } from "./schema.js";

type Schemas = components["schemas"];
export type LoginMethod = Schemas["LoginMethod"];
export type Me = Schemas["MeResponse"];
export type Session = Schemas["SessionResponse"];
export type Tokens = Schemas["TokenResponse"];
export type ConfirmationAction = Schemas["ConfirmationAction"];

/**
 * Proof required by a sensitive change: the current password, or a 6-digit `code` emailed by
 * `requestConfirmation` — the only way for an account created by magic link, which has no password.
 */
export type Confirmation =
	| { password: string; code?: never }
	| { code: string; password?: never };

export interface BauthClientOptions {
	/** bauth base URL, without trailing slash, e.g. `https://auth.example.com`. */
	baseUrl: string;
	/** Client id from bauth.toml. */
	clientId: string;
	/** One of the client's `redirect_uris` in bauth.toml, byte for byte. */
	redirectUri: string;
	/** Custom fetch (SvelteKit's `event.fetch`, Tauri's plugin-http…). Defaults to `globalThis.fetch`. */
	fetch?: typeof globalThis.fetch;
}

export interface LoginFlow {
	flowId: string;
	/** Login screens to offer. */
	methods: LoginMethod[];
	expiresAt: string;
	/**
	 * PKCE secret proving the code exchange comes from whoever started the flow.
	 * For magic links, store it (e.g. `localStorage`: the link opens a new tab) until the link comes back.
	 * Never send it anywhere else.
	 */
	codeVerifier: string;
}

type FetchResult<T> = { data?: T; error?: unknown; response: Response };

async function unwrap<T>(result: Promise<FetchResult<T>>): Promise<T> {
	const { data, error, response } = await result;
	if (!response.ok) throw await BauthError.fromResponse(response, error);
	return data as T;
}

const bearer = (accessToken: string) => ({
	Authorization: `Bearer ${accessToken}`,
});

const form = {
	bodySerializer: (body: Record<string, string | null | undefined>) =>
		new URLSearchParams(
			Object.entries(body).filter(
				(entry): entry is [string, string] => entry[1] != null,
			),
		),
	headers: { "Content-Type": "application/x-www-form-urlencoded" },
};

/** Reads the `#token=…` fragment of an email link (verification, magic link, password reset). */
export function tokenFromUrl(url: string | URL): string | null {
	return new URLSearchParams(new URL(url).hash.slice(1)).get("token");
}

export function createBauthClient(options: BauthClientOptions) {
	const { clientId, redirectUri } = options;
	const api = createFetchClient<paths>({
		baseUrl: options.baseUrl,
		fetch: options.fetch,
	});

	async function exchangeCode(
		code: string,
		codeVerifier: string,
	): Promise<Tokens> {
		const body = {
			grant_type: "authorization_code",
			client_id: clientId,
			code,
			redirect_uri: redirectUri,
			code_verifier: codeVerifier,
		};
		return unwrap(api.POST("/oauth/token", { body, ...form }));
	}

	return {
		/** The typed openapi-fetch client, for anything not wrapped below. */
		api,

		// Login

		async startLogin(state?: string): Promise<LoginFlow> {
			const codeVerifier = generateCodeVerifier();
			const body = {
				client_id: clientId,
				redirect_uri: redirectUri,
				code_challenge: await computeCodeChallenge(codeVerifier),
				code_challenge_method: "S256",
				state: state ?? null,
			};
			const flow = await unwrap(api.POST("/flows/login", { body }));
			return {
				flowId: flow.flow_id,
				methods: flow.methods,
				expiresAt: flow.expires_at,
				codeVerifier,
			};
		},

		/** Password step: returns the code, then call `exchangeCode`. */
		async submitPassword(
			flowId: string,
			email: string,
			password: string,
		): Promise<string> {
			const params = { path: { flow_id: flowId } };
			const result = await unwrap(
				api.POST("/flows/login/{flow_id}/password", {
					params,
					body: { email, password },
				}),
			);
			return result.code;
		},

		/** Starts a flow, checks the password and exchanges the code, in one call. */
		async loginWithPassword(email: string, password: string): Promise<Tokens> {
			const flow = await this.startLogin();
			return exchangeCode(
				await this.submitPassword(flow.flowId, email, password),
				flow.codeVerifier,
			);
		},

		/**
		 * Emails a link and a 6-digit code: to log in, or to create the account on first use when the client
		 * allows sign-up (no password, one email). Same answer whether the account exists or not.
		 */
		async requestMagicLink(flowId: string, email: string): Promise<void> {
			const params = { path: { flow_id: flowId } };
			await unwrap(
				api.POST("/flows/login/{flow_id}/magic-link", {
					params,
					body: { email },
				}),
			);
		},

		/** On the page the magic link opens: returns the code, then call `exchangeCode` with the stored verifier. */
		async confirmMagicLink(token: string): Promise<string> {
			return (
				await unwrap(api.POST("/magic-link/confirm", { body: { token } }))
			).code;
		},

		/**
		 * On the device that asked for the email: returns the code, then call `exchangeCode`.
		 * Only the newest email's code works, for 5 attempts; a wrong one is `invalid_code`.
		 */
		async confirmMagicCode(flowId: string, code: string): Promise<string> {
			const params = { path: { flow_id: flowId } };
			return (
				await unwrap(
					api.POST("/flows/login/{flow_id}/magic-code", {
						params,
						body: { code },
					}),
				)
			).code;
		},

		exchangeCode,

		async refresh(refreshToken: string): Promise<Tokens> {
			const body = {
				grant_type: "refresh_token",
				client_id: clientId,
				refresh_token: refreshToken,
			};
			return unwrap(api.POST("/oauth/token", { body, ...form }));
		},

		/** Logout: revokes the session behind the refresh token. */
		async logout(refreshToken: string): Promise<void> {
			await unwrap(
				api.POST("/oauth/revoke", {
					body: { client_id: clientId, token: refreshToken },
					...form,
				}),
			);
		},

		// Registration and email verification

		/** Same answer whether the email was free or taken. */
		async register(email: string, password: string): Promise<void> {
			await unwrap(
				api.POST("/registration", {
					body: { client_id: clientId, email, password },
				}),
			);
		},

		async resendVerification(email: string): Promise<void> {
			await unwrap(
				api.POST("/verification", { body: { client_id: clientId, email } }),
			);
		},

		/** On the verification page: confirms email verification or an email change. */
		async confirmVerification(token: string): Promise<void> {
			await unwrap(api.POST("/verification/confirm", { body: { token } }));
		},

		// Password reset

		async requestPasswordReset(email: string): Promise<void> {
			await unwrap(
				api.POST("/recovery", { body: { client_id: clientId, email } }),
			);
		},

		/** Sets the new password and logs the user out everywhere. */
		async resetPassword(token: string, password: string): Promise<void> {
			await unwrap(api.POST("/recovery/reset", { body: { token, password } }));
		},

		// Account

		async getMe(accessToken: string): Promise<Me> {
			return unwrap(api.GET("/me", { headers: bearer(accessToken) }));
		},

		async changePassword(
			accessToken: string,
			currentPassword: string,
			newPassword: string,
		): Promise<void> {
			const body = {
				current_password: currentPassword,
				new_password: newPassword,
			};
			await unwrap(
				api.POST("/me/password", { headers: bearer(accessToken), body }),
			);
		},

		/** Emails a 6-digit code to confirm `action`; pass it back as `{ code }`. */
		async requestConfirmation(
			accessToken: string,
			action: ConfirmationAction,
		): Promise<void> {
			await unwrap(
				api.POST("/me/confirmation", {
					headers: bearer(accessToken),
					body: { action },
				}),
			);
		},

		/** Sends a confirmation link to the new address, confirmed with `confirmVerification`. */
		async changeEmail(
			accessToken: string,
			confirmation: Confirmation,
			newEmail: string,
		): Promise<void> {
			const body = { ...confirmation, new_email: newEmail };
			await unwrap(
				api.POST("/me/email", { headers: bearer(accessToken), body }),
			);
		},

		async listSessions(accessToken: string): Promise<Session[]> {
			return unwrap(api.GET("/me/sessions", { headers: bearer(accessToken) }));
		},

		async revokeSession(accessToken: string, sessionId: string): Promise<void> {
			const params = { path: { session_id: sessionId } };
			await unwrap(
				api.DELETE("/me/sessions/{session_id}", {
					headers: bearer(accessToken),
					params,
				}),
			);
		},

		async deleteAccount(
			accessToken: string,
			confirmation: Confirmation,
		): Promise<void> {
			await unwrap(
				api.DELETE("/me", { headers: bearer(accessToken), body: confirmation }),
			);
		},
	};
}

export type BauthClient = ReturnType<typeof createBauthClient>;
