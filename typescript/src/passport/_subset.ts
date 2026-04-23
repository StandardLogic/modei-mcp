/**
 * Subset-permissions + constraints-tightening + expiry-non-extension.
 *
 * Internal module (underscore prefix): shared by `verifier.ts` (verify-time
 * enforcement) and `delegation.ts` (pre-sign validation, lands in C20.5).
 * The pre-sign verdict MUST match the verify-time verdict for identical
 * inputs — same function, same result, both callsites.
 *
 * Mirror of the Python SDK's `modei.passport._subset` and the backend's
 * `src/lib/passports/chain.ts` lines 285–446 (`enforceSubsetPermissions`,
 * `enforceConstraintsTightening`, `checkDimension`, `deepEqual`).
 *
 * Not exposed in the package `exports` map and not emitted as a standalone
 * tsup entry — tsup bundles this module's code inline into `issuer.js` and
 * `verifier.js`. That keeps _subset strictly internal: consumers cannot
 * `import 'modei-typescript/passport/_subset'`.
 *
 * Return shape divergence from the kickoff prompt: this module returns a
 * structured `SubsetCheck { ok, detail }` rather than throwing on
 * violation. Both callers want the `detail` string (verifier populates
 * `ChainVerifyResult.detail`; DelegationBuilder in C20.5 parses it to
 * populate `DelegationSubsetError`'s structured fields). Matches Python.
 */

import type { Envelope, PassportPermission } from './envelope.js';

const NUMERIC_TIGHTEN: ReadonlySet<string> = new Set([
  'max_per_action_cost',
  'max_daily_cost',
  'max_total_cost',
  'rate_limit_per_minute',
  'rate_limit_per_hour',
]);

const SET_INCLUDE: ReadonlySet<string> = new Set([
  'allowed_domains',
  'allowed_paths',
  'allowed_models',
]);

export interface SubsetCheck {
  ok: boolean;
  detail: string | null;
}

const PASSED: SubsetCheck = Object.freeze({ ok: true, detail: null });

function failed(detail: string): SubsetCheck {
  return { ok: false, detail };
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== 'object') return false;
  if (Array.isArray(a)) {
    if (!Array.isArray(b) || a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  if (Array.isArray(b)) return false;
  const aObj = a as Record<string, unknown>;
  const bObj = b as Record<string, unknown>;
  const aKeys = Object.keys(aObj);
  const bKeys = Object.keys(bObj);
  if (aKeys.length !== bKeys.length) return false;
  for (const k of aKeys) {
    if (!Object.prototype.hasOwnProperty.call(bObj, k)) return false;
    if (!deepEqual(aObj[k], bObj[k])) return false;
  }
  return true;
}

function isFiniteNumber(x: unknown): x is number {
  return typeof x === 'number' && Number.isFinite(x);
}

/**
 * Return `{ ok: true }` if `descendantVal` tightens-or-equals `ancestorVal`
 * for the given constraint dimension; otherwise a failure with the
 * spec-required detail message.
 */
export function checkConstraintDimension(
  dim: string,
  ancestorVal: unknown,
  descendantVal: unknown,
): SubsetCheck {
  if (NUMERIC_TIGHTEN.has(dim)) {
    if (!isFiniteNumber(ancestorVal)) {
      return failed(`'${dim}' must be numeric on both sides`);
    }
    if (!isFiniteNumber(descendantVal)) {
      return failed(`'${dim}' must be numeric on both sides`);
    }
    if (descendantVal > ancestorVal) {
      return failed(`'${dim}' descendant=${descendantVal} > ancestor=${ancestorVal}`);
    }
    return PASSED;
  }

  if (SET_INCLUDE.has(dim)) {
    if (!Array.isArray(ancestorVal) || !Array.isArray(descendantVal)) {
      return failed(`'${dim}' must be an array on both sides`);
    }
    const ancSet = new Set(ancestorVal as unknown[]);
    for (const v of descendantVal as unknown[]) {
      if (!ancSet.has(v)) {
        return failed(`'${dim}' descendant entry ${JSON.stringify(v)} not in ancestor`);
      }
    }
    return PASSED;
  }

  // operating_hours and unknown dimensions fall back to deep-equality.
  if (!deepEqual(ancestorVal, descendantVal)) {
    if (dim === 'operating_hours') {
      return failed(
        "'operating_hours' descendant differs from ancestor (deep-equality required)",
      );
    }
    return failed(`unknown constraint dimension '${dim}' must match ancestor exactly`);
  }
  return PASSED;
}

/**
 * Pairwise subset check. For every descendant permission, the ancestor must
 * have a matching `permission_key` AND every constraint dimension in the
 * descendant must tighten-or-equal the ancestor's value. Dimensions absent
 * in the descendant are inherited (§3.5); dimensions absent in the ancestor
 * cannot be added by the descendant.
 */
export function enforceSubsetPermissions(
  ancestor: Envelope,
  descendant: Envelope,
): SubsetCheck {
  const ancestorByKey = new Map<string, PassportPermission>();
  for (const p of ancestor.permissions) {
    ancestorByKey.set(p.permission_key, p);
  }
  for (const descPerm of descendant.permissions) {
    const ancPerm = ancestorByKey.get(descPerm.permission_key);
    if (ancPerm === undefined) {
      return failed(
        `descendant permission '${descPerm.permission_key}' not present in ancestor`,
      );
    }
    for (const [dim, descVal] of Object.entries(descPerm.constraints)) {
      if (!Object.prototype.hasOwnProperty.call(ancPerm.constraints, dim)) {
        return failed(
          `permission '${descPerm.permission_key}': constraint '${dim}' absent in ancestor; descendant cannot add it`,
        );
      }
      const check = checkConstraintDimension(dim, ancPerm.constraints[dim], descVal);
      if (!check.ok) {
        return failed(`permission '${descPerm.permission_key}': ${check.detail ?? ''}`);
      }
    }
  }
  return PASSED;
}

/**
 * True if `descendant.expires_at <= ancestor.expires_at`.
 *
 * Compares the ISO 8601 Z-suffixed millisecond strings lexicographically,
 * which is sound for this format (same result as chronological compare).
 */
export function isExpiryNonExtending(ancestor: Envelope, descendant: Envelope): boolean {
  return descendant.provenance.expires_at <= ancestor.provenance.expires_at;
}
