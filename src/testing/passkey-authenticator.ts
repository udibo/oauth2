/**
 * A software WebAuthn authenticator for tests: it answers registration and
 * authentication options with real, signed ES256 responses, the way a browser
 * and a platform authenticator would.
 *
 * @module
 */

import type {
  PasskeyAuthenticationOptions,
  PasskeyAuthenticationResponse,
  PasskeyRegistrationOptions,
  PasskeyRegistrationResponse,
} from "../identity/passkeys/service.ts";
import { base64urlDecode, base64urlEncode } from "../utils/crypto.ts";

/** Options for {@link TestPasskeyAuthenticator}. */
export interface TestPasskeyAuthenticatorOptions {
  /** The origin the simulated browser reports, such as `https://login.example.com`. */
  origin: string;
  /** Whether the authenticator verifies the person (the UV flag). Defaults to `true`. */
  userVerified?: boolean;
  /**
   * Whether passkeys are synced (backup-eligible and backed up), like a
   * password manager's. Defaults to `true`. `false` behaves like a security key.
   */
  synced?: boolean;
  /**
   * Whether the signature counter increases on each use, like a security key.
   * Defaults to `false`: synced passkeys report `0`.
   */
  countSignatures?: boolean;
}

/** Per-call overrides for {@link TestPasskeyAuthenticator.authenticate}. */
export interface TestPasskeyAuthenticateOptions {
  /** Use this credential instead of the first one the options allow. */
  credentialId?: string;
  /** Report this origin instead of the authenticator's, as a phishing page would. */
  origin?: string;
  /** Override the UV flag for this assertion. */
  userVerified?: boolean;
  /** Report this sign count instead of the next one. */
  signCount?: number;
}

/** A credential the {@link TestPasskeyAuthenticator} holds. */
export interface TestPasskeyCredential {
  /** The credential id, base64url. */
  credentialId: string;
  /** The RP ID it was created for. */
  rpId: string;
  /** The user handle, base64url. */
  userHandle: string;
  /** The current signature counter. */
  signCount: number;
}

interface HeldCredential extends TestPasskeyCredential {
  privateKey: CryptoKey;
}

/**
 * A software authenticator for tests. {@link register} answers
 * `PasskeyService.startRegistration` options and {@link authenticate} answers
 * `startAuthentication` options with responses `PasskeyService` verifies like
 * a browser's. Keys are P-256 (ES256) and the attestation format is `none`.
 *
 * @example
 * ```ts
 * import { TestPasskeyAuthenticator } from "@udibo/oauth2/testing";
 * import type { PasskeyRegistrationOptions } from "@udibo/oauth2/identity/passkeys";
 *
 * declare const options: PasskeyRegistrationOptions;
 * const authenticator = new TestPasskeyAuthenticator({
 *   origin: "https://login.example.com",
 * });
 * const response = await authenticator.register(options);
 * ```
 */
export class TestPasskeyAuthenticator {
  readonly #origin: string;
  readonly #userVerified: boolean;
  readonly #synced: boolean;
  readonly #countSignatures: boolean;
  readonly #credentials: HeldCredential[] = [];

  /** Creates an authenticator with no credentials. */
  constructor(options: TestPasskeyAuthenticatorOptions) {
    this.#origin = options.origin;
    this.#userVerified = options.userVerified ?? true;
    this.#synced = options.synced ?? true;
    this.#countSignatures = options.countSignatures ?? false;
  }

  /** The credentials created so far. */
  get credentials(): TestPasskeyCredential[] {
    return this.#credentials.map(
      ({ credentialId, rpId, userHandle, signCount }) => ({
        credentialId,
        rpId,
        userHandle,
        signCount,
      }),
    );
  }

  /**
   * Create a credential for the options' RP ID and user, and return the
   * response `navigator.credentials.create()` would.
   */
  async register(
    options: PasskeyRegistrationOptions,
    overrides: { origin?: string } = {},
  ): Promise<PasskeyRegistrationResponse> {
    const rpId = options.rp.id;
    if (!rpId) throw new TypeError("registration options carry no rp.id");
    const keyPair = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const credentialIdBytes = crypto.getRandomValues(new Uint8Array(16));
    const credentialId = base64urlEncode(credentialIdBytes);
    const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const coseKey = encodeCbor(
      new Map<number, unknown>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, base64urlDecode(jwk.x ?? "")],
        [-3, base64urlDecode(jwk.y ?? "")],
      ]),
    );
    const signCount = this.#countSignatures ? 1 : 0;
    const attestedCredential = concat(
      new Uint8Array(16),
      new Uint8Array([
        credentialIdBytes.length >> 8,
        credentialIdBytes.length & 0xff,
      ]),
      credentialIdBytes,
      coseKey,
    );
    const authenticatorData = concat(
      await this.#authenticatorDataHeader(
        rpId,
        signCount,
        this.#userVerified,
        true,
      ),
      attestedCredential,
    );
    const clientDataJSON = clientData(
      "webauthn.create",
      options.challenge,
      overrides.origin ?? this.#origin,
    );
    const attestationObject = encodeCbor(
      new Map<string, unknown>([
        ["fmt", "none"],
        ["attStmt", new Map()],
        ["authData", authenticatorData],
      ]),
    );
    this.#credentials.push({
      credentialId,
      rpId,
      userHandle: options.user.id,
      signCount,
      privateKey: keyPair.privateKey,
    });
    return {
      id: credentialId,
      rawId: credentialId,
      type: "public-key",
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: base64urlEncode(clientDataJSON),
        attestationObject: base64urlEncode(attestationObject),
        transports: ["internal", "hybrid"],
      },
    };
  }

  /**
   * Sign the options' challenge with a held credential and return the
   * response `navigator.credentials.get()` would.
   *
   * @throws {Error} when no held credential matches the options.
   */
  async authenticate(
    options: PasskeyAuthenticationOptions,
    overrides: TestPasskeyAuthenticateOptions = {},
  ): Promise<PasskeyAuthenticationResponse> {
    const allowed = new Set(
      (options.allowCredentials ?? []).map((credential) => credential.id),
    );
    const credential = this.#credentials.find(
      (candidate) =>
        candidate.rpId === options.rpId &&
        (overrides.credentialId === undefined
          ? allowed.size === 0 || allowed.has(candidate.credentialId)
          : candidate.credentialId === overrides.credentialId),
    );
    if (!credential) throw new Error("no matching test passkey");
    if (this.#countSignatures) credential.signCount += 1;
    const authenticatorData = await this.#authenticatorDataHeader(
      credential.rpId,
      overrides.signCount ?? credential.signCount,
      overrides.userVerified ?? this.#userVerified,
      false,
    );
    const clientDataJSON = clientData(
      "webauthn.get",
      options.challenge,
      overrides.origin ?? this.#origin,
    );
    const signed = concat(
      authenticatorData,
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", toBuffer(clientDataJSON)),
      ),
    );
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        credential.privateKey,
        toBuffer(signed),
      ),
    );
    return {
      id: credential.credentialId,
      rawId: credential.credentialId,
      type: "public-key",
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: base64urlEncode(clientDataJSON),
        authenticatorData: base64urlEncode(authenticatorData),
        signature: base64urlEncode(derSignature(signature)),
        userHandle: credential.userHandle,
      },
    };
  }

  async #authenticatorDataHeader(
    rpId: string,
    signCount: number,
    userVerified: boolean,
    attestedCredentialData: boolean,
  ): Promise<Uint8Array> {
    const rpIdHash = new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        toBuffer(new TextEncoder().encode(rpId)),
      ),
    );
    const flags =
      0x01 |
      (userVerified ? 0x04 : 0) |
      (this.#synced ? 0x08 | 0x10 : 0) |
      (attestedCredentialData ? 0x40 : 0);
    const counter = new Uint8Array(4);
    new DataView(counter.buffer).setUint32(0, signCount);
    return concat(rpIdHash, new Uint8Array([flags]), counter);
  }
}

function clientData(
  type: string,
  challenge: string,
  origin: string,
): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({ type, challenge, origin, crossOrigin: false }),
  );
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(
    parts.reduce((size, part) => size + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function toBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer;
}

function derSignature(raw: Uint8Array): Uint8Array {
  const integer = (bytes: Uint8Array): Uint8Array => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start += 1;
    const trimmed = bytes.slice(start);
    const padded =
      (trimmed[0] ?? 0) & 0x80 ? concat(new Uint8Array([0]), trimmed) : trimmed;
    return concat(new Uint8Array([0x02, padded.length]), padded);
  };
  const body = concat(integer(raw.slice(0, 32)), integer(raw.slice(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

function encodeCbor(value: unknown): Uint8Array {
  if (typeof value === "number") {
    return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return concat(cborHead(3, bytes.length), bytes);
  }
  if (value instanceof Uint8Array) {
    return concat(cborHead(2, value.length), value);
  }
  if (value instanceof Map) {
    const entries = [...value.entries()].flatMap(([key, entry]) => [
      encodeCbor(key),
      encodeCbor(entry),
    ]);
    return concat(cborHead(5, value.size), ...entries);
  }
  throw new TypeError("unsupported CBOR value");
}

function cborHead(major: number, length: number): Uint8Array {
  const type = major << 5;
  if (length < 24) return new Uint8Array([type | length]);
  if (length < 0x100) return new Uint8Array([type | 24, length]);
  return new Uint8Array([type | 25, length >> 8, length & 0xff]);
}
