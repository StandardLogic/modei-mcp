/**
 * PassportIssuer — construct and sign self-issued v2 envelopes.
 *
 * Port of Python `modei.passport.issuer`. Spec §11.1, §3.1. Delegation
 * issuance lives in `delegation.ts` (C20.5); this module only handles
 * `issuer.type = 'self'`.
 *
 * Signing pipeline (matches backend + Python byte-for-byte):
 *   1. Build canonical v2 envelope object.
 *   2. RFC 8785 canonicalize via `canonicalizeStrict` → UTF-8 bytes.
 *   3. Sign with Ed25519 over the full canonical bytes.
 *   4. Return the envelope + detached base64 signature.
 *
 * API divergences from the Python SDK (intentional):
 * - Takes `expiresAt: Date` (absolute) instead of Python's
 *   `expires_in: timedelta` (relative). TS has no native duration type;
 *   absolute timestamps match the envelope's underlying `expires_at`
 *   field, and the fixture parity test benefits from fixed-literal values.
 *   Callers compute deltas themselves:
 *   `new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)`.
 * - `identityClaim` lives on the constructor options only (Python parity);
 *   not per-issue. Call a new issuer to change the claim.
 */

import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { randomUUID } from 'node:crypto';

import { deriveSelfAgentId } from './agentId.js';
import { canonicalizeStrict } from './canonical.js';
import type { AgentCredentials } from './credentials.js';
import type {
  Envelope,
  PassportPermission,
  SignedPassport,
} from './envelope.js';

// sync SHA-512 hook for @noble/ed25519 v3; required before any sign/verify/getPublicKey call.
// Idempotent — credentials.ts may have already set this; reassigning a function property
// is zero-cost and defends against import-order bugs when issuer.ts is imported standalone.
ed.hashes.sha512 = sha512;

/** Per-envelope canonical byte-length cap (spec §2.1). */
export const MAX_CANONICAL_ENVELOPE_BYTES = 64 * 1024;

export interface PassportIssuerOptions {
  /**
   * String populated into `identity.agent_name` on every issued envelope.
   * L0: unverified display text. L0.5 (deferred): DNS-verifiable.
   *
   * If `null` or omitted, the issued envelope has `identity.agent_name = null`.
   * Such envelopes are LOCALLY valid and can be used on the inline path, but
   * `POST /api/passports/register` rejects them server-side (route requires
   * a non-empty agent_name). Pass a non-null claim for registerable passports.
   */
  identityClaim?: string | null;
}

export interface SelfIssuePermission {
  permission_key: string;
  constraints?: Record<string, unknown>;
}

export interface SelfIssueOptions {
  permissions: SelfIssuePermission[];
  /** Absolute expiration time. Required. */
  expiresAt: Date;
  /** Default `false`. Set `true` to allow this envelope to be a delegation parent. */
  delegationAuthority?: boolean;
  /** L0.5 reserved field; default `[]`. */
  verificationEvidence?: unknown[];
  /** Override for tests / fixture reproduction. Default: `pp_self_<32 hex>`. */
  passportId?: string;
  /** Override for tests / fixture reproduction. Default: `new Date()`. */
  issuedAt?: Date;
}

function formatIsoMsZ(d: Date): string {
  // `toISOString` already emits "YYYY-MM-DDTHH:MM:SS.sssZ" — no normalization
  // needed. Matches backend `new Date().toISOString()` and Python's
  // `_format_iso_ms_z` exactly.
  return d.toISOString();
}

function hexSha256Pubkey(pubkey: Uint8Array): string {
  return bytesToHex(sha256(pubkey));
}

function generatePassportId(): string {
  // crypto.randomUUID() returns 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx' — 36 chars.
  // Strip dashes (and lowercase, already lowercase from randomUUID) to match
  // Python's `uuid.uuid4().hex` format: 32 hex chars.
  return `pp_self_${randomUUID().replace(/-/g, '')}`;
}

export class PassportIssuer {
  readonly #credentials: AgentCredentials;
  readonly #identityClaim: string | null;

  constructor(credentials: AgentCredentials, options: PassportIssuerOptions = {}) {
    this.#credentials = credentials;
    this.#identityClaim = options.identityClaim ?? null;
  }

  selfIssue(options: SelfIssueOptions): SignedPassport {
    const creds = this.#credentials;
    const pubkeyB64 = Buffer.from(creds.publicKey).toString('base64');

    const issuedAtDate = options.issuedAt ?? new Date();
    const expiresAtDate = options.expiresAt;

    const envelope: Envelope = {
      schema_version: 2,
      passport_id: options.passportId ?? generatePassportId(),
      identity: {
        agent_id: deriveSelfAgentId(creds.publicKey),
        agent_name: this.#identityClaim,
        public_key: pubkeyB64,
      },
      permissions: options.permissions.map<PassportPermission>((p) => ({
        permission_key: p.permission_key,
        constraints: p.constraints ?? {},
      })),
      provenance: {
        issuer: {
          type: 'self',
          id: 'self:' + hexSha256Pubkey(creds.publicKey),
          key_id: 'self',
        },
        gate_id: null,
        catalog_content_hash: null,
        catalog_version: null,
        delegation_chain: null,
        issued_at: formatIsoMsZ(issuedAtDate),
        expires_at: formatIsoMsZ(expiresAtDate),
      },
      delegation_authority: options.delegationAuthority ?? false,
      verification_evidence: options.verificationEvidence ?? [],
    };

    const signatureB64 = signEnvelope(envelope, creds.privateKey);
    return { envelope, signature: signatureB64 };
  }
}

/**
 * Internal helper: canonicalize + size-check + sign + base64-encode.
 * Exported for use by `DelegationBuilder` (C20.5).
 */
export function signEnvelope(envelope: Envelope, privateKey: Uint8Array): string {
  const canonical = canonicalizeStrict(envelope);
  if (canonical.length > MAX_CANONICAL_ENVELOPE_BYTES) {
    throw new Error(
      `envelope_too_large: canonical envelope is ${canonical.length} bytes, ` +
        `max ${MAX_CANONICAL_ENVELOPE_BYTES}`,
    );
  }
  const sigBytes = ed.sign(canonical, privateKey);
  return Buffer.from(sigBytes).toString('base64');
}
