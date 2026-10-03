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

/** A magic code login in progress: what `requestMagicCode` keeps and `submitMagicCode` needs. */
export interface PendingMagicCode {
	flowId: string;
	/** PKCE secret proving the code exchange comes from the device that asked for the email. */
	codeVerifier: string;
	email: string;
	/** When bauth forgets the flow (ISO 8601). */
	expiresAt: string;
}

/** Where the login in progress lives between the two screens: `localStorage`, a cookie… */
export interface FlowStore {
	read(): PendingMagicCode | undefined | Promise<PendingMagicCode | undefined>;
	/** `undefined` forgets the flow. */
	write(flow: PendingMagicCode | undefined): void | Promise<void>;
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

/** Reads the `#token=…` fragment of an email link (magic link, email change). */
export function tokenFromUrl(url: string | URL): string | null {
	return new URLSearchParams(new URL(url).hash.slice(1)).get("token");
}

export function createBauthClient(options: BauthClientOptions) {
	// Fail now rather than deep in the first auth call (typically an unset environment variable).
	for (const name of ["baseUrl", "clientId", "redirectUri"] as const) {
		if (typeof options[name] !== "string" || !options[name].trim()) {
			throw new TypeError(`createBauthClient: \`${name}\` is required`);
		}
	}
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

	const client = {
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

		/**
		 * Emails a link and a 6-digit code: to log in, or to create the account on first use when the client
		 * allows sign-up (one email). Same answer whether the account exists or not.
		 * Returns when the flow now expires: each email keeps it alive as long as itself.
		 */
		async requestMagicLink(flowId: string, email: string): Promise<string> {
			const params = { path: { flow_id: flowId } };
			const sent = await unwrap(
				api.POST("/flows/login/{flow_id}/magic-link", {
					params,
					body: { email },
				}),
			);
			return sent.expires_at;
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

		/**
		 * Emails a code (and a link) for `email`, and keeps the flow in `store`. Asking again for the
		 * same address continues the same flow, so only the newest email's code works; once bauth
		 * refuses more emails on it (3 per flow) or the flow expired, a new one is started.
		 */
		async requestMagicCode(email: string, store: FlowStore): Promise<void> {
			const pending = await store.read();
			const isLive =
				pending?.email === email && Date.parse(pending.expiresAt) > Date.now();
			if (pending && isLive) {
				try {
					const expiresAt = await client.requestMagicLink(pending.flowId, email);
					await store.write({ ...pending, expiresAt });
					return;
				} catch (error) {
					const isExhausted =
						error instanceof BauthError &&
						(error.code === "rate_limited" || error.code === "flow_expired");
					if (!isExhausted) throw error;
				}
			}
			const flow = await client.startLogin();
			const expiresAt = await client.requestMagicLink(flow.flowId, email);
			await store.write({
				flowId: flow.flowId,
				codeVerifier: flow.codeVerifier,
				email,
				expiresAt,
			});
		},

		/**
		 * Turns the code typed by the user into tokens, for the flow in `store`, then forgets the
		 * flow. Anything but digits is ignored (`123 456`). No flow in progress is `flow_expired`;
		 * a wrong code is `invalid_code` and keeps the flow for another try.
		 */
		async submitMagicCode(code: string, store: FlowStore): Promise<Tokens> {
			const pending = await store.read();
			if (!pending) {
				throw new BauthError(400, "flow_expired", "no magic code login in progress");
			}
			const authorizationCode = await client.confirmMagicCode(
				pending.flowId,
				code.replace(/\D/g, ""),
			);
			const tokens = await exchangeCode(authorizationCode, pending.codeVerifier);
			await store.write(undefined);
			return tokens;
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

		// Account

		async getMe(accessToken: string): Promise<Me> {
			return unwrap(api.GET("/me", { headers: bearer(accessToken) }));
		},

		/** Emails a 6-digit code to confirm `action` (`change_email`, `delete_account`). */
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

		/** Sends a confirmation link to the new address, confirmed with `confirmEmailChange`. */
		async changeEmail(
			accessToken: string,
			code: string,
			newEmail: string,
		): Promise<void> {
			const body = { code, new_email: newEmail };
			await unwrap(
				api.POST("/me/email", { headers: bearer(accessToken), body }),
			);
		},

		/** On the `email_change_url` page the email change link opens: moves the account to the new address. */
		async confirmEmailChange(token: string): Promise<void> {
			await unwrap(api.POST("/email-change/confirm", { body: { token } }));
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

		async deleteAccount(accessToken: string, code: string): Promise<void> {
			await unwrap(
				api.DELETE("/me", { headers: bearer(accessToken), body: { code } }),
			);
		},
	};
	return client;
}

export type BauthClient = ReturnType<typeof createBauthClient>;
