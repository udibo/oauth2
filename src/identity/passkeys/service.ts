/**
 * The passkey orchestrator: WebAuthn registration and authentication
 * ceremonies over an app-owned {@link PasskeyStore} and
 * {@link PasskeyChallengeStore}. Cryptographic verification is delegated to
 * `@simplewebauthn/server`; this layer owns the policy around it — no
 * attestation, discoverable credentials, single-use challenges, a per-user
 * cap, sign-count clone detection, and the usual identity seams.
 *
 * @module
 */

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";

import { base64urlEncode, randomToken } from "../../utils/crypto.ts";
import { IdentityError } from "../errors.ts";
import {
  dispatchIdentityEvent,
  type IdentityEvent,
  type IdentityEventHook,
} from "../events.ts";
import { enforceRateLimit, type RateLimiterLike } from "../rate-limit.ts";

/**
 * The options a browser passes to `navigator.credentials.create()`, in the
 * W3C JSON form (`PublicKeyCredential.parseCreationOptionsFromJSON`).
 */
export type PasskeyRegistrationOptions = PublicKeyCredentialCreationOptionsJSON;

/**
 * The options a browser passes to `navigator.credentials.get()`, in the W3C
 * JSON form (`PublicKeyCredential.parseRequestOptionsFromJSON`).
 */
export type PasskeyAuthenticationOptions =
  PublicKeyCredentialRequestOptionsJSON;

/** The browser's `navigator.credentials.create()` result, as `toJSON()` serializes it. */
export type PasskeyRegistrationResponse = RegistrationResponseJSON;

/** The browser's `navigator.credentials.get()` result, as `toJSON()` serializes it. */
export type PasskeyAuthenticationResponse = AuthenticationResponseJSON;

/**
 * Who the ceremony is for. A passkey is bound to `id` (the RP ID) forever, so
 * pass it as explicit configuration — the registrable host your sign-in page
 * is served on — and never derive it from a request's `Host` header.
 */
export interface PasskeyRelyingParty {
  /** The RP ID: a host such as `login.example.com`, with no scheme or port. */
  id: string;
  /** The name a browser may show in its passkey prompt. */
  name: string;
  /**
   * Every origin a response may come from, such as
   * `https://login.example.com`. A response from any other origin is
   * refused — this check is what makes a passkey phishing-resistant.
   */
  origins: readonly string[];
}

/** The account a new passkey is created for. */
export interface PasskeyUser {
  /**
   * Your stable user id. It becomes the credential's user handle (UTF-8, at
   * most 64 bytes), so a passkey signs in the same account even after the
   * person changes their email or username. Do not use personal data here.
   */
  id: string;
  /** The account name a passkey manager shows, typically an email or username. */
  name: string;
  /** A friendlier name a passkey manager may show. Defaults to `name`. */
  displayName?: string;
}

/** A stored passkey, as {@link PasskeyStore} persists it. Nothing here is secret. */
export interface Passkey {
  /**
   * The credential id, base64url. Chosen by the registering client, not by
   * the server, so it must be unique across every row
   * {@link PasskeyStore.findPasskey} can return.
   */
  credentialId: string;
  /** The account this passkey signs in to. */
  userId: string;
  /** The RP ID the passkey was created under; it can be used only there. */
  rpId: string;
  /** The COSE-encoded public key. */
  publicKey: Uint8Array;
  /** The last signature counter seen. Synced passkeys always report `0`. */
  signCount: number;
  /** Transport hints the browser reported (`internal`, `hybrid`, `usb`, …). */
  transports: string[];
  /**
   * The authenticator model id the authenticator *claims*. Unattested, so
   * treat it as a display hint only — never as a security decision.
   */
  aaguid: string;
  /**
   * Whether the passkey may be synced between devices (the backup-eligible
   * flag). `false` means it is bound to one device or security key.
   */
  multiDevice: boolean;
  /** Whether the passkey was synced or backed up when last seen. */
  backedUp: boolean;
  /** A label the person can recognize and change. */
  name: string;
  /** When it was registered. */
  createdAt: Date;
  /** When it last signed in, or `null` when never. */
  lastUsedAt: Date | null;
}

/** The server-side half of one ceremony, held in a {@link PasskeyChallengeStore}. */
export interface PasskeyChallenge {
  /** The base64url challenge the browser must sign. */
  challenge: string;
  /** Which ceremony issued it; a challenge never crosses ceremonies. */
  ceremony: "registration" | "authentication";
  /** The RP ID the ceremony runs under. */
  rpId: string;
  /**
   * The user the ceremony is bound to: always set for registration, set for
   * authentication only when the user was already identified (a second
   * factor or a re-authentication).
   */
  userId?: string;
  /** Epoch milliseconds after which the challenge is refused. */
  expiresAt: number;
}

/**
 * App-owned, short-lived storage for ceremony challenges. {@link take} **must
 * be atomic** — read and delete in one step (Redis `GETDEL`, a `DELETE …
 * RETURNING`) — because that is what makes each challenge single-use under
 * concurrent submission. Expire entries yourself at or after `expiresAt`.
 */
export interface PasskeyChallengeStore {
  /** Store a challenge under an unguessable ceremony id. */
  put(ceremonyId: string, challenge: PasskeyChallenge): Promise<void>;
  /** Atomically remove and return the challenge, or `undefined` when absent. */
  take(ceremonyId: string): Promise<PasskeyChallenge | undefined>;
}

/** What {@link PasskeyStore.addPasskey} did. */
export type PasskeyAddResult = "added" | "duplicate" | "limit_reached";

/** A verified use of a passkey, for {@link PasskeyStore.recordUse}. */
export interface PasskeyUse {
  /** The sign count read before verification — the compare-and-set guard. */
  previousSignCount: number;
  /** The sign count the authenticator just reported. */
  signCount: number;
  /** The backup state the authenticator just reported. */
  backedUp: boolean;
  /** When the passkey was used. */
  usedAt: Date;
}

/**
 * App-owned persistence for {@link PasskeyService}. Implement it over your
 * database; {@link MemoryPasskeyStore} ships for development and tests.
 * Public keys are not secrets, so nothing here needs encryption.
 *
 * Two methods are concurrency guards and **must be atomic**:
 * {@link addPasskey} (uniqueness of the credential id and the per-user cap in
 * one statement or transaction) and {@link recordUse} (a conditional update on
 * the previous sign count).
 */
export interface PasskeyStore {
  /** The user's passkeys, oldest first; only those under `rpId` when given. */
  listPasskeys(userId: string, rpId?: string): Promise<Passkey[]>;
  /**
   * The passkey with this credential id, or `undefined`. Credential ids are
   * chosen by the registering client, so the uniqueness {@link addPasskey}
   * enforces must span everything this lookup searches — never narrower.
   */
  findPasskey(credentialId: string): Promise<Passkey | undefined>;
  /**
   * Insert the passkey unless its credential id already exists
   * (`"duplicate"`) or the user already holds `limit` passkeys
   * (`"limit_reached"`).
   */
  addPasskey(passkey: Passkey, limit: number): Promise<PasskeyAddResult>;
  /**
   * Record a sign-in: set the sign count, backup state, and last-used time,
   * but only while the stored sign count still equals
   * `use.previousSignCount`. Return whether the row changed — `false` when
   * the passkey was removed meanwhile, so a removed passkey cannot finish one
   * last sign-in.
   */
  recordUse(credentialId: string, use: PasskeyUse): Promise<boolean>;
  /** Rename one of the user's passkeys; `false` when it is not theirs. */
  renamePasskey(
    userId: string,
    credentialId: string,
    name: string,
  ): Promise<boolean>;
  /** Delete one of the user's passkeys; `false` when it is not theirs. */
  removePasskey(userId: string, credentialId: string): Promise<boolean>;
}

/** Options for {@link PasskeyService}. */
export interface PasskeyServiceOptions {
  /** Where passkeys live. */
  store: PasskeyStore;
  /** Where in-flight ceremony challenges live. */
  challenges: PasskeyChallengeStore;
  /** The most passkeys one user may register. Defaults to `25`. */
  maxPasskeysPerUser?: number;
  /** How long a ceremony stays open, in milliseconds. Defaults to five minutes. */
  challengeTtlMs?: number;
  /**
   * Throttles {@link PasskeyService.finishAuthentication}: per user for a
   * ceremony bound to one, and per the caller's `rateLimitKey` for passkey
   * sign-in (unthrottled here without one — put your own per-IP limit in
   * front). Every finish counts, including one naming no live ceremony, so a
   * caller cannot flood `passkey.verify.failed` events. Excess attempts emit
   * `passkey.verify.rate_limited` and, under `protectionMode: "enforce"`,
   * throw `IdentityError` `rate_limited`.
   */
  rateLimiter?: RateLimiterLike;
  /** `"enforce"` (default) applies the rate limit; `"log-only"` only reports it. */
  protectionMode?: "enforce" | "log-only";
  /** Receives `passkey.*` {@link IdentityEvent}s for audit capture. */
  onEvent?: IdentityEventHook;
}

/** A started ceremony: send `options` to the browser and keep `ceremonyId`. */
export interface PasskeyCeremony<Options> {
  /**
   * The key the challenge is stored under. Bind it to the browser that started
   * the ceremony — an HttpOnly cookie, a server session — and pass it back to
   * the matching `finish*` call.
   */
  ceremonyId: string;
  /** What the browser needs for `navigator.credentials`. */
  options: Options;
}

/** Arguments for {@link PasskeyService.startRegistration}. */
export interface StartPasskeyRegistrationOptions {
  /** The relying party the passkey binds to. */
  relyingParty: PasskeyRelyingParty;
  /** The signed-in account the passkey is for. */
  user: PasskeyUser;
}

/** Arguments for {@link PasskeyService.finishRegistration}. */
export interface FinishPasskeyRegistrationOptions {
  /** The same relying party the ceremony started with. */
  relyingParty: PasskeyRelyingParty;
  /** From {@link PasskeyService.startRegistration}. */
  ceremonyId: string;
  /** The signed-in account; must be the one the ceremony started for. */
  userId: string;
  /** The browser's response. */
  response: PasskeyRegistrationResponse;
  /** A label for the new passkey. Defaults to `"Passkey"`. */
  name?: string;
}

/**
 * Why a registration was refused:
 *
 * - `"expired_challenge"` — the ceremony id is unknown, spent, or expired.
 * - `"invalid"` — the response failed verification, or belongs to another
 *   user, relying party, or ceremony.
 * - `"duplicate"` — this credential is already registered.
 * - `"limit_reached"` — the user already holds the maximum number of passkeys.
 */
export type PasskeyRegistrationFailureReason =
  | "expired_challenge"
  | "invalid"
  | "duplicate"
  | "limit_reached";

/** The result of {@link PasskeyService.finishRegistration}. */
export type PasskeyRegistration =
  | { registered: false; reason: PasskeyRegistrationFailureReason }
  | {
      registered: true;
      /** The stored passkey. */
      passkey: Passkey;
      /** Whether the person was verified (PIN or biometric) while creating it. */
      userVerified: boolean;
    };

/** Arguments for {@link PasskeyService.startAuthentication}. */
export interface StartPasskeyAuthenticationOptions {
  /** The relying party to authenticate against. */
  relyingParty: PasskeyRelyingParty;
  /**
   * The already-identified user, for a second factor or re-authentication.
   * Their passkeys are listed in `allowCredentials`. Omit it for passkey
   * sign-in, which lists nothing and so cannot reveal whether an account
   * exists.
   */
  userId?: string;
}

/** Arguments for {@link PasskeyService.finishAuthentication}. */
export interface FinishPasskeyAuthenticationOptions {
  /** The same relying party the ceremony started with. */
  relyingParty: PasskeyRelyingParty;
  /** From {@link PasskeyService.startAuthentication}. */
  ceremonyId: string;
  /** The browser's response. */
  response: PasskeyAuthenticationResponse;
  /**
   * The user this sign-in must belong to — required whenever a user is
   * already identified (a second factor, a re-authentication). The ceremony
   * must have been started for exactly this user; one started without a user
   * is refused, so a person cannot answer someone else's challenge with their
   * own passkey. Omit it only for passkey sign-in.
   */
  userId?: string;
  /**
   * The rate-limit key for a sign-in with no identified user, such as
   * `${tenantId}:${clientIp}`. Without it, only ceremonies bound to a user are
   * throttled (per user); credential ids are never used as keys, since anyone
   * who learns one could exhaust its owner's budget.
   */
  rateLimitKey?: string;
}

/**
 * Why an authentication was refused. Internal detail — tell the person only
 * that the passkey did not work:
 *
 * - `"expired_challenge"` — the ceremony id is unknown, spent, or expired.
 * - `"unknown_passkey"` — no stored passkey has this credential id under
 *   this relying party.
 * - `"invalid"` — the signature, origin, RP ID, challenge, user-presence flag,
 *   or user handle did not verify, or the passkey is not the bound user's.
 * - `"sign_count"` — the authenticator's counter went backwards: a possible
 *   cloned authenticator. Worth an alert.
 * - `"replayed"` — a concurrent sign-in already advanced this passkey.
 */
export type PasskeyVerifyFailureReason =
  | "expired_challenge"
  | "unknown_passkey"
  | "invalid"
  | "sign_count"
  | "replayed";

/** The result of {@link PasskeyService.finishAuthentication}. */
export type PasskeyVerification =
  | { valid: false; reason: PasskeyVerifyFailureReason }
  | {
      valid: true;
      /** The account the passkey belongs to. */
      userId: string;
      /** The passkey, with its use recorded. */
      passkey: Passkey;
      /**
       * Whether the authenticator verified the person (PIN or biometric). A
       * user-verified passkey is a multi-factor authenticator on its own;
       * without it, the passkey proves possession only.
       */
      userVerified: boolean;
    };

/**
 * The RFC 8176 / OpenID EAP `amr` value for a passkey: proof of possession of
 * a key. `hwk` and `swk` would claim to know where the key lives, which an
 * unattested passkey cannot show.
 */
export const PASSKEY_AMR = "pop";

const DEFAULT_MAX_PASSKEYS = 25;
const DEFAULT_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const MAX_NAME_LENGTH = 64;
const MAX_USER_HANDLE_BYTES = 64;
const SUPPORTED_ALGORITHMS = [-8, -7, -257];

/**
 * Orchestrates passkey registration, sign-in, and management over app-owned
 * stores. Every passkey is discoverable, attestation is never requested, and
 * user verification is preferred and reported rather than required, so
 * security keys without a PIN still work as a second factor. Deciding what a
 * verified passkey is worth — a first factor, a second factor, whether it
 * satisfies your MFA policy — and minting the session are the app's job.
 *
 * @example Register, then sign in
 * ```ts
 * import {
 *   MemoryPasskeyChallengeStore,
 *   MemoryPasskeyStore,
 *   PasskeyService,
 * } from "@udibo/oauth2/identity/passkeys";
 *
 * const passkeys = new PasskeyService({
 *   store: new MemoryPasskeyStore(),
 *   challenges: new MemoryPasskeyChallengeStore(),
 * });
 * const relyingParty = {
 *   id: "login.example.com",
 *   name: "Example",
 *   origins: ["https://login.example.com"],
 * };
 * const user = { id: "user-1", name: "ada@example.com" };
 *
 * const registration = await passkeys.startRegistration({ relyingParty, user });
 * // keep registration.ceremonyId in an HttpOnly cookie; the browser runs
 * // navigator.credentials.create() with registration.options and posts back:
 * declare const createResponse: import("@udibo/oauth2/identity/passkeys").PasskeyRegistrationResponse;
 * await passkeys.finishRegistration({
 *   relyingParty,
 *   ceremonyId: registration.ceremonyId,
 *   userId: user.id,
 *   response: createResponse,
 * });
 *
 * const signIn = await passkeys.startAuthentication({ relyingParty });
 * declare const getResponse: import("@udibo/oauth2/identity/passkeys").PasskeyAuthenticationResponse;
 * const result = await passkeys.finishAuthentication({
 *   relyingParty,
 *   ceremonyId: signIn.ceremonyId,
 *   response: getResponse,
 * });
 * if (result.valid) {
 *   // run your MFA policy for result.userId, then start a session
 * }
 * ```
 */
export class PasskeyService {
  readonly #store: PasskeyStore;
  readonly #challenges: PasskeyChallengeStore;
  readonly #maxPasskeys: number;
  readonly #challengeTtlMs: number;
  readonly #rateLimiter?: RateLimiterLike;
  readonly #enforce: boolean;
  readonly #onEvent?: IdentityEventHook;

  /**
   * Builds the service around app-owned stores.
   *
   * @throws {TypeError} when `maxPasskeysPerUser` or `challengeTtlMs` is not a
   * positive integer, so a miswired deploy fails at startup.
   */
  constructor(options: PasskeyServiceOptions) {
    const max = options.maxPasskeysPerUser ?? DEFAULT_MAX_PASSKEYS;
    const ttl = options.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS;
    if (!Number.isInteger(max) || max <= 0) {
      throw new TypeError("maxPasskeysPerUser must be a positive integer");
    }
    if (!Number.isInteger(ttl) || ttl <= 0) {
      throw new TypeError("challengeTtlMs must be a positive integer");
    }
    this.#store = options.store;
    this.#challenges = options.challenges;
    this.#maxPasskeys = max;
    this.#challengeTtlMs = ttl;
    this.#rateLimiter = options.rateLimiter;
    this.#enforce = (options.protectionMode ?? "enforce") === "enforce";
    this.#onEvent = options.onEvent;
  }

  /** The most passkeys one user may register. */
  get maxPasskeysPerUser(): number {
    return this.#maxPasskeys;
  }

  /**
   * Begin adding a passkey to a signed-in account. The user's existing
   * passkeys under this relying party are excluded so an authenticator is not
   * registered twice. Call it only after confirming it is really the account
   * holder — a stolen session must not be able to add its own passkey.
   *
   * @throws {IdentityError} `passkey_limit_reached` when the user already
   * holds the maximum number of passkeys.
   * @throws {TypeError} when the user id is longer than 64 UTF-8 bytes or the
   * relying party lists no origins.
   */
  async startRegistration(
    options: StartPasskeyRegistrationOptions,
  ): Promise<PasskeyCeremony<PasskeyRegistrationOptions>> {
    const { relyingParty, user } = options;
    assertRelyingParty(relyingParty);
    const userHandle = new TextEncoder().encode(user.id);
    if (
      userHandle.byteLength === 0 ||
      userHandle.byteLength > MAX_USER_HANDLE_BYTES
    ) {
      throw new TypeError("user.id must be 1 to 64 UTF-8 bytes");
    }
    const existing = await this.#store.listPasskeys(user.id);
    if (existing.length >= this.#maxPasskeys) {
      throw new IdentityError(
        "passkey_limit_reached",
        `a user may register at most ${this.#maxPasskeys} passkeys`,
      );
    }
    const passkeyOptions = await generateRegistrationOptions({
      rpID: relyingParty.id,
      rpName: relyingParty.name,
      userID: userHandle,
      userName: user.name,
      userDisplayName: user.displayName ?? user.name,
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      timeout: this.#challengeTtlMs,
      attestationType: "none",
      excludeCredentials: existing
        .filter((passkey) => passkey.rpId === relyingParty.id)
        .map((passkey) => ({
          id: passkey.credentialId,
          transports: passkey.transports,
        })),
      authenticatorSelection: {
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "preferred",
      },
      supportedAlgorithmIDs: SUPPORTED_ALGORITHMS,
    });
    const ceremonyId = await this.#putChallenge({
      challenge: passkeyOptions.challenge,
      ceremony: "registration",
      rpId: relyingParty.id,
      userId: user.id,
    });
    return { ceremonyId, options: passkeyOptions };
  }

  /**
   * Verify the browser's response and store the new passkey. The challenge
   * is spent whatever the outcome. Attestation is never relied on: a
   * statement the authenticator volunteers must still be well-formed, but the
   * passkey is stored as unattested and no authenticator is preferred.
   */
  async finishRegistration(
    options: FinishPasskeyRegistrationOptions,
  ): Promise<PasskeyRegistration> {
    const { relyingParty, userId } = options;
    const challenge = await this.#takeChallenge(options.ceremonyId);
    if (!challenge) {
      return await this.#registrationFailed(userId, "expired_challenge");
    }
    if (
      challenge.ceremony !== "registration" ||
      challenge.rpId !== relyingParty.id ||
      challenge.userId !== userId
    ) {
      return await this.#registrationFailed(userId, "invalid");
    }
    let verified;
    try {
      verified = await verifyRegistrationResponse({
        response: options.response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: [...relyingParty.origins],
        expectedRPID: relyingParty.id,
        requireUserPresence: true,
        requireUserVerification: false,
        supportedAlgorithmIDs: SUPPORTED_ALGORITHMS,
      });
    } catch {
      return await this.#registrationFailed(userId, "invalid");
    }
    if (!verified.verified) {
      return await this.#registrationFailed(userId, "invalid");
    }
    const info = verified.registrationInfo;
    const passkey: Passkey = {
      credentialId: info.credential.id,
      userId,
      rpId: relyingParty.id,
      publicKey: new Uint8Array(info.credential.publicKey),
      signCount: info.credential.counter,
      transports: [...(info.credential.transports ?? [])],
      aaguid: info.aaguid,
      multiDevice: info.credentialDeviceType === "multiDevice",
      backedUp: info.credentialBackedUp,
      name: normalizeName(options.name),
      createdAt: new Date(),
      lastUsedAt: null,
    };
    const added = await this.#store.addPasskey(passkey, this.#maxPasskeys);
    if (added !== "added") {
      return await this.#registrationFailed(userId, added);
    }
    await this.#emit({
      type: "passkey.registered",
      userId,
      credentialId: passkey.credentialId,
      multiDevice: passkey.multiDevice,
    });
    return { registered: true, passkey, userVerified: info.userVerified };
  }

  /**
   * Begin a passkey sign-in. Without `userId` the browser offers every
   * passkey it holds for this relying party (the account is learned from the
   * response); with it, only that user's passkeys are allowed.
   *
   * @throws {IdentityError} `passkey_not_registered` when `userId` is given
   * and the user has no passkey under this relying party.
   */
  async startAuthentication(
    options: StartPasskeyAuthenticationOptions,
  ): Promise<PasskeyCeremony<PasskeyAuthenticationOptions>> {
    const { relyingParty, userId } = options;
    assertRelyingParty(relyingParty);
    let allowCredentials: { id: string; transports: string[] }[] | undefined;
    if (userId !== undefined) {
      const passkeys = await this.#store.listPasskeys(userId, relyingParty.id);
      if (passkeys.length === 0) {
        throw new IdentityError(
          "passkey_not_registered",
          "the user has no passkey for this relying party",
        );
      }
      allowCredentials = passkeys.map((passkey) => ({
        id: passkey.credentialId,
        transports: passkey.transports,
      }));
    }
    const passkeyOptions = await generateAuthenticationOptions({
      rpID: relyingParty.id,
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      timeout: this.#challengeTtlMs,
      userVerification: "preferred",
      ...(allowCredentials ? { allowCredentials } : {}),
    });
    const ceremonyId = await this.#putChallenge({
      challenge: passkeyOptions.challenge,
      ceremony: "authentication",
      rpId: relyingParty.id,
      ...(userId !== undefined ? { userId } : {}),
    });
    return { ceremonyId, options: passkeyOptions };
  }

  /**
   * Verify a sign-in response. The challenge is spent whatever the outcome;
   * on success the passkey's sign count and last-used time are recorded and
   * the rate-limit window resets. This never starts a session — apply your
   * account checks and MFA policy to `userId` first.
   *
   * @throws {IdentityError} `rate_limited` when a `rateLimiter` is configured,
   * `protectionMode` is `"enforce"`, and the limit is hit.
   */
  async finishAuthentication(
    options: FinishPasskeyAuthenticationOptions,
  ): Promise<PasskeyVerification> {
    const { relyingParty, response } = options;
    const challenge = await this.#takeChallenge(options.ceremonyId);
    const credentialId = credentialIdOf(response);
    const expectedUserId = options.userId;
    const boundUserId = challenge?.userId;
    const throttledUserId = expectedUserId ?? boundUserId;
    const rateKey =
      throttledUserId !== undefined
        ? `passkey:verify:${throttledUserId}`
        : options.rateLimitKey !== undefined
          ? `passkey:verify:anonymous:${options.rateLimitKey}`
          : undefined;
    if (rateKey !== undefined) {
      await this.#throttle(rateKey, throttledUserId, credentialId);
    }
    if (!challenge) {
      return await this.#verifyFailed(
        "expired_challenge",
        credentialId,
        expectedUserId,
      );
    }
    if (
      challenge.ceremony !== "authentication" ||
      challenge.rpId !== relyingParty.id ||
      (expectedUserId !== undefined && boundUserId !== expectedUserId)
    ) {
      return await this.#verifyFailed("invalid", credentialId, throttledUserId);
    }
    const passkey = credentialId
      ? await this.#store.findPasskey(credentialId)
      : undefined;
    if (!passkey || passkey.rpId !== relyingParty.id) {
      return await this.#verifyFailed(
        "unknown_passkey",
        credentialId,
        boundUserId,
      );
    }
    if (
      (boundUserId !== undefined && passkey.userId !== boundUserId) ||
      !userHandleMatches(response.response?.userHandle, passkey.userId)
    ) {
      return await this.#verifyFailed(
        "invalid",
        credentialId,
        boundUserId ?? passkey.userId,
      );
    }
    let verified;
    try {
      verified = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: [...relyingParty.origins],
        expectedRPID: relyingParty.id,
        credential: {
          id: passkey.credentialId,
          publicKey: new Uint8Array(passkey.publicKey),
          counter: 0,
          transports: passkey.transports,
        },
        requireUserVerification: false,
      });
    } catch {
      return await this.#verifyFailed("invalid", credentialId, passkey.userId);
    }
    if (!verified.verified) {
      return await this.#verifyFailed("invalid", credentialId, passkey.userId);
    }
    const info = verified.authenticationInfo;
    if (
      (info.newCounter > 0 || passkey.signCount > 0) &&
      info.newCounter <= passkey.signCount
    ) {
      return await this.#verifyFailed(
        "sign_count",
        credentialId,
        passkey.userId,
      );
    }
    const usedAt = new Date();
    const recorded = await this.#store.recordUse(credentialId, {
      previousSignCount: passkey.signCount,
      signCount: info.newCounter,
      backedUp: info.credentialBackedUp,
      usedAt,
    });
    if (!recorded) {
      return await this.#verifyFailed("replayed", credentialId, passkey.userId);
    }
    if (rateKey !== undefined) await this.#resetThrottle(rateKey);
    await this.#emit({
      type: "passkey.verify.succeeded",
      userId: passkey.userId,
      credentialId,
      userVerified: info.userVerified,
    });
    return {
      valid: true,
      userId: passkey.userId,
      userVerified: info.userVerified,
      passkey: {
        ...passkey,
        signCount: info.newCounter,
        backedUp: info.credentialBackedUp,
        lastUsedAt: usedAt,
      },
    };
  }

  /** The user's passkeys, oldest first; only those under `rpId` when given. */
  listPasskeys(userId: string, rpId?: string): Promise<Passkey[]> {
    return this.#store.listPasskeys(userId, rpId);
  }

  /**
   * Rename one of the user's passkeys. The name is trimmed and capped at 64
   * characters; an empty name becomes `"Passkey"`. Returns `false` when the
   * passkey is not the user's.
   */
  async renamePasskey(
    userId: string,
    credentialId: string,
    name: string,
  ): Promise<boolean> {
    const renamed = await this.#store.renamePasskey(
      userId,
      credentialId,
      normalizeName(name),
    );
    if (renamed) {
      await this.#emit({ type: "passkey.renamed", userId, credentialId });
    }
    return renamed;
  }

  /**
   * Remove one of the user's passkeys. Returns `false` when it is not theirs.
   * Gate the route behind a fresh confirmation, and refuse it yourself when it
   * would leave the account with no way to sign in — only the app knows
   * which other methods are usable.
   */
  async removePasskey(userId: string, credentialId: string): Promise<boolean> {
    const removed = await this.#store.removePasskey(userId, credentialId);
    if (removed) {
      await this.#emit({ type: "passkey.removed", userId, credentialId });
    }
    return removed;
  }

  async #putChallenge(
    challenge: Omit<PasskeyChallenge, "expiresAt">,
  ): Promise<string> {
    const ceremonyId = randomToken(32);
    await this.#challenges.put(ceremonyId, {
      ...challenge,
      expiresAt: Date.now() + this.#challengeTtlMs,
    });
    return ceremonyId;
  }

  async #takeChallenge(
    ceremonyId: string,
  ): Promise<PasskeyChallenge | undefined> {
    if (typeof ceremonyId !== "string" || ceremonyId === "") return undefined;
    const challenge = await this.#challenges.take(ceremonyId);
    if (!challenge || challenge.expiresAt <= Date.now()) return undefined;
    return challenge;
  }

  async #registrationFailed(
    userId: string,
    reason: PasskeyRegistrationFailureReason,
  ): Promise<PasskeyRegistration> {
    await this.#emit({ type: "passkey.registration.failed", userId, reason });
    return { registered: false, reason };
  }

  async #verifyFailed(
    reason: PasskeyVerifyFailureReason,
    credentialId: string,
    userId?: string,
  ): Promise<PasskeyVerification> {
    await this.#emit({
      type: "passkey.verify.failed",
      reason,
      ...(credentialId ? { credentialId } : {}),
      ...(userId !== undefined ? { userId } : {}),
    });
    return { valid: false, reason };
  }

  #throttle(
    key: string,
    userId: string | undefined,
    credentialId: string,
  ): Promise<void> {
    return enforceRateLimit({
      rateLimiter: this.#rateLimiter,
      key,
      message: "too many passkey attempts",
      enforce: this.#enforce,
      event: {
        type: "passkey.verify.rate_limited",
        ...(userId !== undefined ? { userId } : {}),
        ...(credentialId ? { credentialId } : {}),
      },
      emit: (event) => this.#emit(event),
    });
  }

  async #resetThrottle(key: string): Promise<void> {
    try {
      await this.#rateLimiter?.reset(key);
    } catch (error) {
      console.error(
        "[@udibo/oauth2] passkey rate-limit reset failed; the window stays " +
          "filled until it lapses:",
        error instanceof Error ? error.message : error,
      );
    }
  }

  #emit(event: IdentityEvent): Promise<void> {
    return dispatchIdentityEvent(this.#onEvent, "passkeys", event);
  }
}

function assertRelyingParty(relyingParty: PasskeyRelyingParty): void {
  if (!relyingParty.id || relyingParty.origins.length === 0) {
    throw new TypeError("relyingParty needs an id and at least one origin");
  }
}

function normalizeName(name: string | undefined): string {
  const trimmed = (name ?? "").trim().slice(0, MAX_NAME_LENGTH);
  return trimmed === "" ? "Passkey" : trimmed;
}

const MAX_CREDENTIAL_ID_LENGTH = 1366;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

function credentialIdOf(response: PasskeyAuthenticationResponse): string {
  const id: unknown = response?.id;
  return typeof id === "string" &&
    id.length <= MAX_CREDENTIAL_ID_LENGTH &&
    BASE64URL.test(id)
    ? id
    : "";
}

function userHandleMatches(
  userHandle: string | undefined,
  userId: string,
): boolean {
  if (userHandle === undefined || userHandle === "") return true;
  return userHandle === base64urlEncode(new TextEncoder().encode(userId));
}

/**
 * In-memory {@link PasskeyStore} for development and tests. State is lost on
 * restart.
 */
export class MemoryPasskeyStore implements PasskeyStore {
  #passkeys = new Map<string, Passkey>();

  /** The user's passkeys, oldest first. */
  listPasskeys(userId: string, rpId?: string): Promise<Passkey[]> {
    return Promise.resolve(
      [...this.#passkeys.values()]
        .filter(
          (passkey) =>
            passkey.userId === userId &&
            (rpId === undefined || passkey.rpId === rpId),
        )
        .map(copyPasskey),
    );
  }

  /** The passkey with this credential id, or `undefined`. */
  findPasskey(credentialId: string): Promise<Passkey | undefined> {
    const passkey = this.#passkeys.get(credentialId);
    return Promise.resolve(passkey ? copyPasskey(passkey) : undefined);
  }

  /** Insert unless duplicate or over the per-user limit. */
  addPasskey(passkey: Passkey, limit: number): Promise<PasskeyAddResult> {
    if (this.#passkeys.has(passkey.credentialId)) {
      return Promise.resolve("duplicate");
    }
    const held = [...this.#passkeys.values()].filter(
      (existing) => existing.userId === passkey.userId,
    ).length;
    if (held >= limit) return Promise.resolve("limit_reached");
    this.#passkeys.set(passkey.credentialId, copyPasskey(passkey));
    return Promise.resolve("added");
  }

  /** Record a use while the sign count still matches. */
  recordUse(credentialId: string, use: PasskeyUse): Promise<boolean> {
    const passkey = this.#passkeys.get(credentialId);
    if (!passkey || passkey.signCount !== use.previousSignCount) {
      return Promise.resolve(false);
    }
    passkey.signCount = use.signCount;
    passkey.backedUp = use.backedUp;
    passkey.lastUsedAt = use.usedAt;
    return Promise.resolve(true);
  }

  /** Rename one of the user's passkeys. */
  renamePasskey(
    userId: string,
    credentialId: string,
    name: string,
  ): Promise<boolean> {
    const passkey = this.#passkeys.get(credentialId);
    if (passkey?.userId !== userId) return Promise.resolve(false);
    passkey.name = name;
    return Promise.resolve(true);
  }

  /** Delete one of the user's passkeys. */
  removePasskey(userId: string, credentialId: string): Promise<boolean> {
    if (this.#passkeys.get(credentialId)?.userId !== userId) {
      return Promise.resolve(false);
    }
    this.#passkeys.delete(credentialId);
    return Promise.resolve(true);
  }
}

/**
 * In-memory {@link PasskeyChallengeStore} for development and tests. Expired
 * entries are dropped as new ones arrive.
 */
export class MemoryPasskeyChallengeStore implements PasskeyChallengeStore {
  #challenges = new Map<string, PasskeyChallenge>();

  /** Store a challenge. */
  put(ceremonyId: string, challenge: PasskeyChallenge): Promise<void> {
    const now = Date.now();
    for (const [id, stored] of this.#challenges) {
      if (stored.expiresAt <= now) this.#challenges.delete(id);
    }
    this.#challenges.set(ceremonyId, { ...challenge });
    return Promise.resolve();
  }

  /** Remove and return a challenge. */
  take(ceremonyId: string): Promise<PasskeyChallenge | undefined> {
    const challenge = this.#challenges.get(ceremonyId);
    this.#challenges.delete(ceremonyId);
    return Promise.resolve(challenge);
  }
}

function copyPasskey(passkey: Passkey): Passkey {
  return {
    ...passkey,
    publicKey: new Uint8Array(passkey.publicKey),
    transports: [...passkey.transports],
  };
}
