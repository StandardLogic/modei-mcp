/**
 * Error hierarchy + CanonicalizationError migration contract.
 *
 * Introduced in C20.4. Validates the new `ModeiError` shared base and the
 * four delegation error classes declared for C20.5's `DelegationBuilder`.
 * Also locks the migration invariants for `CanonicalizationError`:
 *   1. Still importable from both `./passport/canonical` (re-export) and
 *      `./passport/errors` (new home).
 *   2. Still NOT `instanceof TypeError` (C20.1 contract-pin preserved).
 *   3. `reasonCode` and `path` fields preserved.
 *   4. Now `instanceof ModeiError` (strictly additive superclass).
 */

import { describe, expect, it } from 'vitest';

import { CanonicalizationError as CanonicalizationErrorViaCanonical } from '../src/passport/canonical.js';
import {
  CanonicalizationError,
  DelegationAuthorityMissingError,
  DelegationChainTooDeepError,
  DelegationError,
  DelegationSubsetError,
  ModeiError,
} from '../src/passport/errors.js';

describe('ModeiError', () => {
  it('extends Error', () => {
    const err = new ModeiError('test');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(ModeiError);
    expect(err.name).toBe('ModeiError');
    expect(err.message).toBe('test');
  });
});

describe('CanonicalizationError migration', () => {
  it('is re-exported from canonical.ts at the same identity', () => {
    // The re-export path and the new-home path resolve to the exact same class.
    expect(CanonicalizationErrorViaCanonical).toBe(CanonicalizationError);
  });

  it('is now instanceof ModeiError (new relationship in C20.4)', () => {
    const err = new CanonicalizationError('non_finite_number_in_canonical_input', ['x']);
    expect(err).toBeInstanceOf(ModeiError);
    expect(err).toBeInstanceOf(CanonicalizationError);
    expect(err).toBeInstanceOf(Error);
  });

  it('is still NOT instanceof TypeError (C20.1 contract-pin preserved)', () => {
    const err = new CanonicalizationError('non_finite_number_in_canonical_input', []);
    expect(err).not.toBeInstanceOf(TypeError);
  });

  it('preserves reasonCode and path fields', () => {
    const err = new CanonicalizationError('non_finite_number_in_canonical_input', ['a', '1'], 'NaN');
    expect(err.reasonCode).toBe('non_finite_number_in_canonical_input');
    expect(err.path).toEqual(['a', '1']);
    expect(err.message).toBe('non_finite_number_in_canonical_input at a.1: NaN');
  });
});

describe('DelegationError tree', () => {
  it('DelegationError extends ModeiError', () => {
    const err = new DelegationError('d');
    expect(err).toBeInstanceOf(ModeiError);
    expect(err).toBeInstanceOf(DelegationError);
    expect(err.name).toBe('DelegationError');
  });

  it('DelegationSubsetError extends DelegationError with structured fields', () => {
    const err = new DelegationSubsetError({
      permissionKey: 'api:read',
      dimension: 'max_per_action_cost',
      ancestorValue: 100,
      descendantValue: 500,
      detail: "permission 'api:read': 'max_per_action_cost' descendant=500 > ancestor=100",
    });
    expect(err).toBeInstanceOf(DelegationError);
    expect(err).toBeInstanceOf(ModeiError);
    expect(err).toBeInstanceOf(Error);
    expect(err.permissionKey).toBe('api:read');
    expect(err.dimension).toBe('max_per_action_cost');
    expect(err.ancestorValue).toBe(100);
    expect(err.descendantValue).toBe(500);
    expect(err.name).toBe('DelegationSubsetError');
  });

  it('DelegationChainTooDeepError carries chainLength and maxDepth', () => {
    const err = new DelegationChainTooDeepError(6);
    expect(err).toBeInstanceOf(DelegationError);
    expect(err.chainLength).toBe(6);
    expect(err.maxDepth).toBe(5);
    expect(err.message).toContain('chain length 6');
    expect(err.message).toContain('max 5');
  });

  it('DelegationAuthorityMissingError extends DelegationError', () => {
    const err = new DelegationAuthorityMissingError();
    expect(err).toBeInstanceOf(DelegationError);
    expect(err).toBeInstanceOf(ModeiError);
    expect(err.name).toBe('DelegationAuthorityMissingError');
    expect(err.message).toContain('delegation_authority=false');
  });
});
