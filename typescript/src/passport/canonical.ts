/**
 * RFC 8785 canonicalizer — strict wrapper around `json-canonicalize`.
 *
 * Mirrors the backend's `canonicalizeStrict` (`src/lib/canon/canonicalize.ts`)
 * and the Python SDK's `canonicalize_strict` (`modei.passport.canonical`).
 * Cross-SDK byte-equality against both is a release invariant; see spec §11.2
 * and §13 row 23.
 *
 * Non-finite number handling: the pre-walk rejects `NaN`, `+Infinity`, and
 * `-Infinity` with a `CanonicalizationError` carrying
 * `reasonCode = 'non_finite_number_in_canonical_input'` and a path pointing at
 * the offending value. Only after a clean walk do we delegate to
 * `json-canonicalize`. Without the pre-walk, JS would serialize these to the
 * string `"null"` (JSON.stringify behavior), silently diverging from the
 * backend and the Python SDK which both reject.
 *
 * `canonicalize` returns a UTF-8 string; we encode to `Uint8Array` via
 * `TextEncoder` so the returned bytes are directly comparable to the Python
 * SDK's `bytes` return.
 */

import { canonicalize } from 'json-canonicalize';

import { CanonicalizationError } from './errors.js';

// Re-export for path stability. Migrated to errors.ts in C20.4 so the SDK's
// full error tree lives in one place, but existing
// `import { CanonicalizationError } from '.../passport/canonical'` calls
// continue to resolve. The class now extends `ModeiError` instead of `Error`
// directly; behavior is strictly additive (instanceof Error still holds).
export { CanonicalizationError } from './errors.js';

function walk(value: unknown, path: readonly string[]): void {
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      const kind = Number.isNaN(value) ? 'NaN' : value > 0 ? '+Infinity' : '-Infinity';
      throw new CanonicalizationError('non_finite_number_in_canonical_input', path, kind);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      walk(value[i], [...path, String(i)]);
    }
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      walk(v, [...path, k]);
    }
    return;
  }
  // strings, booleans, null, undefined, bigint, symbol — no-ops at this layer.
  // `canonicalize` itself handles the JSON-representability of the remaining
  // types consistently with the backend.
}

const encoder = new TextEncoder();

/**
 * RFC 8785 canonicalize with non-finite-number rejection.
 *
 * Returns the canonical UTF-8 bytes. Throws `CanonicalizationError` if `value`
 * contains `NaN`, `+Infinity`, or `-Infinity` anywhere in its tree.
 */
export function canonicalizeStrict(value: unknown): Uint8Array {
  walk(value, []);
  return encoder.encode(canonicalize(value));
}
