/**
 * PassportVerifier — local signature + chain verification.
 *
 * Port of Python `modei.passport.verifier`. Spec §5.1, §5.2. Local-only:
 * no DB, no HTTP. Platform- and gate-issued envelopes (or delegated
 * envelopes whose chain root is platform/gate) return
 * `signature_key_unavailable` — backend key resolution required.
 *
 * Mirrors backend `verifyPassportWithChain` (`src/lib/passports/chain.ts`):
 *   - shape check → size cap → single-passport path or chain path
 *   - chain path: depth ≤ 5, root-not-delegate, per-link delegation_authority,
 *     per-link signature, pairwise subset permissions (§3.4) + constraints
 *     tightening (§3.5) + expiry non-extension (§3.3)
 */

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';

import { enforceSubsetPermissions, isExpiryNonExtending } from './_subset.js';
import { canonicalizeStrict } from './canonical.js';
import {
  type DelegationChainEntry,
  type Envelope,
  envelopeSchema,
} from './envelope.js';
import { MAX_CANONICAL_ENVELOPE_BYTES } from './issuer.js';
import type { PassportVerifyReasonCode } from './reasons.js';
import { deriveTier, type TrustTier } from './tier.js';

// sync SHA-512 hook for @noble/ed25519 v3; required before any sign/verify/getPublicKey call.
// Idempotent — credentials.ts / issuer.ts may have already set this; reassigning a
// function property is zero-cost and defends against import-order bugs.
ed.hashes.sha512 = sha512;

export const MAX_DELEGATION_DEPTH = 5;
export const ED25519_SIGNATURE_BYTES = 64;
export const ED25519_PUBLIC_KEY_BYTES = 32;

export type ChainVerifyResult =
  | { valid: true; tier: TrustTier }
  | { valid: false; reasonCode: PassportVerifyReasonCode; detail?: string };

function ok(tier: TrustTier): ChainVerifyResult {
  return { valid: true, tier };
}

function err(reasonCode: PassportVerifyReasonCode, detail?: string): ChainVerifyResult {
  return detail !== undefined ? { valid: false, reasonCode, detail } : { valid: false, reasonCode };
}

function decodeB64FixedLength(s: unknown, expectedLen: number): Uint8Array | null {
  if (typeof s !== 'string' || s.length === 0) return null;
  // Reject any character outside the standard base64 alphabet (incl. `=` pad,
  // no whitespace). `Buffer.from` is lenient otherwise.
  if (!/^[A-Za-z0-9+/]+=*$/.test(s)) return null;
  const decoded = new Uint8Array(Buffer.from(s, 'base64'));
  if (decoded.length !== expectedLen) return null;
  return decoded;
}

function parseEnvelope(
  input: unknown,
): { envelope: Envelope; result?: undefined } | { envelope?: undefined; result: ChainVerifyResult } {
  // Peek at raw `schema_version` before Zod parse to preserve the
  // `unsupported_schema_version` vs `invalid_envelope_shape` distinction.
  // Mirrors Python's _parse_envelope peek.
  if (input !== null && typeof input === 'object' && 'schema_version' in input) {
    const sv = input.schema_version;
    if (typeof sv === 'number' && Number.isInteger(sv) && sv !== 2) {
      return { result: err('unsupported_schema_version', `schema_version=${sv}, expected 2`) };
    }
  }

  const parsed = envelopeSchema.safeParse(input);
  if (!parsed.success) {
    const firstIssue = parsed.error.issues[0];
    const detail = firstIssue ? `${firstIssue.path.join('.')}: ${firstIssue.message}` : parsed.error.message;
    return { result: err('invalid_envelope_shape', detail) };
  }
  return { envelope: parsed.data };
}

function assertCanonicalSize(envelope: Envelope): ChainVerifyResult | null {
  // Size the envelope with delegation_chain stripped — the chain's own
  // bytes are counted per-link separately. Sizing the outer WITH chain
  // would double-count and reject legitimate deep chains.
  const stripped: Envelope = {
    ...envelope,
    provenance: { ...envelope.provenance, delegation_chain: null },
  };
  const canonical = canonicalizeStrict(stripped);
  if (canonical.length > MAX_CANONICAL_ENVELOPE_BYTES) {
    return err(
      'envelope_too_large',
      `canonical envelope is ${canonical.length} bytes, max ${MAX_CANONICAL_ENVELOPE_BYTES}`,
    );
  }
  return null;
}

function verifySignatureOverEnvelope(
  envelope: Envelope,
  signatureB64: string,
  signerPublicKeyB64: string,
): ChainVerifyResult | null {
  const sigBytes = decodeB64FixedLength(signatureB64, ED25519_SIGNATURE_BYTES);
  if (sigBytes === null) return err('signature_malformed');

  const pubBytes = decodeB64FixedLength(signerPublicKeyB64, ED25519_PUBLIC_KEY_BYTES);
  if (pubBytes === null) return err('public_key_malformed');

  const canonical = canonicalizeStrict(envelope);

  let valid: boolean;
  try {
    valid = ed.verify(sigBytes, canonical, pubBytes);
  } catch (e) {
    const name = e instanceof Error ? e.constructor.name : typeof e;
    return err('signature_invalid', `crypto verify raised: ${name}`);
  }
  return valid ? null : err('signature_invalid');
}

function resolveSignerLocal(
  envelope: Envelope,
): { key: string; result?: undefined } | { key?: undefined; result: ChainVerifyResult } {
  const issuerType = envelope.provenance.issuer.type;
  if (issuerType === 'self') {
    return { key: envelope.identity.public_key };
  }
  if (issuerType === 'delegate') {
    const chain = envelope.provenance.delegation_chain;
    if (chain === null || chain.length === 0) {
      return {
        result: err(
          'delegation_chain_invalid_root',
          "issuer.type='delegate' but delegation_chain is null/empty",
        ),
      };
    }
    const last = chain[chain.length - 1];
    if (last === undefined) {
      return { result: err('delegation_chain_invalid_root', 'chain access out of bounds') };
    }
    return { key: last.passport_json.identity.public_key };
  }
  if (issuerType === 'platform' || issuerType === 'gate') {
    return {
      result: err(
        'signature_key_unavailable',
        `issuer type '${issuerType}' requires backend key resolution; ` +
          'PassportVerifier is local-only in v1.0',
      ),
    };
  }
  // envelopeSchema's z.enum rules this out, but defend defensively.
  return { result: err('invalid_envelope_shape', `unknown issuer.type=${String(issuerType)}`) };
}

function prefixDetail(base: ChainVerifyResult, prefix: string): ChainVerifyResult {
  if (base.valid) return base;
  const detail = base.detail !== undefined ? `${prefix}: ${base.detail}` : prefix;
  return { valid: false, reasonCode: base.reasonCode, detail };
}

export class PassportVerifier {
  verify(envelopeOrDict: unknown, signatureB64: string): ChainVerifyResult {
    let envelope: Envelope;
    if (this.#looksLikeEnvelope(envelopeOrDict)) {
      envelope = envelopeOrDict;
    } else {
      const parsed = parseEnvelope(envelopeOrDict);
      if (parsed.result !== undefined) return parsed.result;
      envelope = parsed.envelope;
    }

    const sizeErr = assertCanonicalSize(envelope);
    if (sizeErr !== null) return sizeErr;

    const chain = envelope.provenance.delegation_chain;
    if (chain === null) {
      return this.#verifySingle(envelope, signatureB64);
    }
    return this.#verifyChain(envelope, signatureB64, chain);
  }

  #looksLikeEnvelope(input: unknown): input is Envelope {
    // Quick structural check — if the caller passed an `Envelope` instance
    // (i.e., something already produced by Zod parse or manually shaped to
    // match), skip re-parsing. Mirrors Python's `isinstance(_, Envelope)`
    // shortcut. We still re-validate by Zod if the quick check fails.
    return (
      input !== null &&
      typeof input === 'object' &&
      (input as { schema_version?: unknown }).schema_version === 2 &&
      typeof (input as { passport_id?: unknown }).passport_id === 'string' &&
      'provenance' in input &&
      'identity' in input
    );
  }

  #verifySingle(envelope: Envelope, signatureB64: string): ChainVerifyResult {
    const resolved = resolveSignerLocal(envelope);
    if (resolved.result !== undefined) return resolved.result;
    const sigErr = verifySignatureOverEnvelope(envelope, signatureB64, resolved.key);
    if (sigErr !== null) return sigErr;
    return ok(deriveTier(envelope));
  }

  #verifyChain(
    leaf: Envelope,
    leafSignatureB64: string,
    chain: DelegationChainEntry[],
  ): ChainVerifyResult {
    if (chain.length > MAX_DELEGATION_DEPTH) {
      return err(
        'delegation_chain_too_deep',
        `chain length ${chain.length} exceeds max ${MAX_DELEGATION_DEPTH}`,
      );
    }
    if (chain.length === 0) {
      return err('delegation_chain_invalid_root', 'delegation_chain is empty array');
    }
    const root = chain[0];
    if (root === undefined) {
      return err('delegation_chain_invalid_root', 'chain[0] access out of bounds');
    }
    if (root.passport_json.provenance.delegation_chain !== null) {
      return err('delegation_chain_invalid_root', 'chain[0].provenance.delegation_chain is not null');
    }

    // Per-link size + delegation_authority.
    for (let i = 0; i < chain.length; i++) {
      const link = chain[i];
      if (link === undefined) continue;
      const sizeErr = assertCanonicalSize(link.passport_json);
      if (sizeErr !== null) return prefixDetail(sizeErr, `chain[${i}]`);
      if (link.passport_json.delegation_authority !== true) {
        return err(
          'delegation_authority_missing',
          `chain[${i}].delegation_authority is not true`,
        );
      }
    }

    // chain[0] signer resolved via same logic as single-passport verify.
    const rootSigner = resolveSignerLocal(root.passport_json);
    if (rootSigner.result !== undefined) return prefixDetail(rootSigner.result, 'chain[0]');
    const rootSigErr = verifySignatureOverEnvelope(
      root.passport_json,
      root.signature,
      rootSigner.key,
    );
    if (rootSigErr !== null) return prefixDetail(rootSigErr, 'chain[0]');

    // chain[i] for i≥1 signed by chain[i-1].identity.public_key.
    for (let i = 1; i < chain.length; i++) {
      const prev = chain[i - 1];
      const cur = chain[i];
      if (prev === undefined || cur === undefined) continue;
      const signerKey = prev.passport_json.identity.public_key;
      const sigErr = verifySignatureOverEnvelope(cur.passport_json, cur.signature, signerKey);
      if (sigErr !== null) return prefixDetail(sigErr, `chain[${i}]`);
    }

    // Leaf signer = last chain entry's identity.
    const lastChainEntry = chain[chain.length - 1];
    if (lastChainEntry === undefined) {
      return err('delegation_chain_invalid_root', 'chain access out of bounds');
    }
    const leafSignerKey = lastChainEntry.passport_json.identity.public_key;
    const leafErr = verifySignatureOverEnvelope(leaf, leafSignatureB64, leafSignerKey);
    if (leafErr !== null) return prefixDetail(leafErr, 'leaf');

    // Pairwise subset + expiry walk: chain[0] → ... → chain[last] → leaf.
    for (let i = 0; i < chain.length - 1; i++) {
      const a = chain[i];
      const b = chain[i + 1];
      if (a === undefined || b === undefined) continue;
      const subset = enforceSubsetPermissions(a.passport_json, b.passport_json);
      if (!subset.ok) {
        return err('permission_elevation_in_chain', `chain[${i}]→chain[${i + 1}]: ${subset.detail ?? ''}`);
      }
      if (!isExpiryNonExtending(a.passport_json, b.passport_json)) {
        return err('expiry_extension_in_chain', `chain[${i}]→chain[${i + 1}]`);
      }
    }
    const leafSubset = enforceSubsetPermissions(lastChainEntry.passport_json, leaf);
    if (!leafSubset.ok) {
      return err(
        'permission_elevation_in_chain',
        `chain[${chain.length - 1}]→leaf: ${leafSubset.detail ?? ''}`,
      );
    }
    if (!isExpiryNonExtending(lastChainEntry.passport_json, leaf)) {
      return err('expiry_extension_in_chain', `chain[${chain.length - 1}]→leaf`);
    }

    return ok(deriveTier(root.passport_json));
  }
}
