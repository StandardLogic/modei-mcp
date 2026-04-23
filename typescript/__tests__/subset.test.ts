/**
 * Subset-permissions + constraints-tightening + expiry-non-extension unit tests.
 *
 * Ports the logic coverage from Python's test_delegation.py subset-violation
 * tests and test_verifier.py elevation test — re-expressed as unit tests of
 * the pure `enforceSubsetPermissions` / `isExpiryNonExtending` functions.
 * Mirror of spec §3.4, §3.5.
 */

import { describe, expect, it } from 'vitest';

import {
  checkConstraintDimension,
  enforceSubsetPermissions,
  isExpiryNonExtending,
} from '../src/passport/_subset.js';
import type { Envelope, PassportPermission } from '../src/passport/envelope.js';

function envWith(
  permissions: PassportPermission[],
  expiresAt = '2026-05-22T00:00:00.000Z',
): Envelope {
  return {
    schema_version: 2,
    passport_id: 'pp_x',
    identity: { agent_id: 'a', agent_name: null, public_key: 'k' },
    permissions,
    provenance: {
      issuer: { type: 'self', id: 'self:x', key_id: 'self' },
      gate_id: null,
      catalog_content_hash: null,
      catalog_version: null,
      delegation_chain: null,
      issued_at: '2026-04-22T00:00:00.000Z',
      expires_at: expiresAt,
    },
    delegation_authority: false,
    verification_evidence: [],
  };
}

describe('enforceSubsetPermissions', () => {
  it('ok: identical envelopes', () => {
    const p: PassportPermission[] = [{ permission_key: 'api:read', constraints: {} }];
    expect(enforceSubsetPermissions(envWith(p), envWith(p)).ok).toBe(true);
  });

  it('ok: descendant drops a constraint (inherits from ancestor)', () => {
    const anc = envWith([
      { permission_key: 'api:read', constraints: { max_per_action_cost: 100 } },
    ]);
    const dec = envWith([{ permission_key: 'api:read', constraints: {} }]);
    expect(enforceSubsetPermissions(anc, dec).ok).toBe(true);
  });

  it('ok: descendant tightens numeric constraint', () => {
    const anc = envWith([
      { permission_key: 'api:read', constraints: { max_per_action_cost: 500 } },
    ]);
    const dec = envWith([
      { permission_key: 'api:read', constraints: { max_per_action_cost: 100 } },
    ]);
    expect(enforceSubsetPermissions(anc, dec).ok).toBe(true);
  });

  it('fail: descendant adds a permission absent from ancestor', () => {
    const anc = envWith([{ permission_key: 'api:read', constraints: {} }]);
    const dec = envWith([{ permission_key: 'api:write', constraints: {} }]);
    const result = enforceSubsetPermissions(anc, dec);
    expect(result.ok).toBe(false);
    expect(result.detail).toContain("'api:write' not present in ancestor");
  });

  it('fail: descendant loosens a numeric constraint', () => {
    const anc = envWith([
      { permission_key: 'api:read', constraints: { max_per_action_cost: 100 } },
    ]);
    const dec = envWith([
      { permission_key: 'api:read', constraints: { max_per_action_cost: 500 } },
    ]);
    const result = enforceSubsetPermissions(anc, dec);
    expect(result.ok).toBe(false);
    expect(result.detail).toContain('descendant=500 > ancestor=100');
  });

  it('fail: descendant adds a constraint dim absent in ancestor', () => {
    const anc = envWith([{ permission_key: 'api:read', constraints: {} }]);
    const dec = envWith([
      { permission_key: 'api:read', constraints: { max_per_action_cost: 100 } },
    ]);
    const result = enforceSubsetPermissions(anc, dec);
    expect(result.ok).toBe(false);
    expect(result.detail).toContain("'max_per_action_cost' absent in ancestor");
  });

  it('ok: descendant set-include is a subset of ancestor', () => {
    const anc = envWith([
      {
        permission_key: 'http:fetch',
        constraints: { allowed_domains: ['a.com', 'b.com', 'c.com'] },
      },
    ]);
    const dec = envWith([
      { permission_key: 'http:fetch', constraints: { allowed_domains: ['a.com', 'b.com'] } },
    ]);
    expect(enforceSubsetPermissions(anc, dec).ok).toBe(true);
  });

  it('fail: descendant set-include has element not in ancestor', () => {
    const anc = envWith([
      { permission_key: 'http:fetch', constraints: { allowed_domains: ['a.com', 'b.com'] } },
    ]);
    const dec = envWith([
      {
        permission_key: 'http:fetch',
        constraints: { allowed_domains: ['a.com', 'evil.com'] },
      },
    ]);
    const result = enforceSubsetPermissions(anc, dec);
    expect(result.ok).toBe(false);
    expect(result.detail).toContain("'allowed_domains'");
    expect(result.detail).toContain('"evil.com"');
  });

  it('ok: operating_hours deep-equal match', () => {
    const hours = { mon: '09-17', tue: '09-17' };
    const anc = envWith([
      { permission_key: 'api:read', constraints: { operating_hours: hours } },
    ]);
    const dec = envWith([
      { permission_key: 'api:read', constraints: { operating_hours: { ...hours } } },
    ]);
    expect(enforceSubsetPermissions(anc, dec).ok).toBe(true);
  });

  it('fail: operating_hours differ (deep-equality required)', () => {
    const anc = envWith([
      {
        permission_key: 'api:read',
        constraints: { operating_hours: { mon: '09-17' } },
      },
    ]);
    const dec = envWith([
      {
        permission_key: 'api:read',
        constraints: { operating_hours: { mon: '00-23' } },
      },
    ]);
    const result = enforceSubsetPermissions(anc, dec);
    expect(result.ok).toBe(false);
    expect(result.detail).toContain('operating_hours');
  });
});

describe('checkConstraintDimension numeric-type guarding', () => {
  it('fail: ancestor is not numeric', () => {
    const result = checkConstraintDimension('max_per_action_cost', 'not a number', 100);
    expect(result.ok).toBe(false);
    expect(result.detail).toContain('must be numeric');
  });

  it('fail: descendant is not numeric', () => {
    const result = checkConstraintDimension('max_per_action_cost', 100, true);
    expect(result.ok).toBe(false);
    expect(result.detail).toContain('must be numeric');
  });
});

describe('isExpiryNonExtending', () => {
  it('ok: descendant expires before ancestor', () => {
    const anc = envWith([], '2026-12-31T00:00:00.000Z');
    const dec = envWith([], '2026-06-30T00:00:00.000Z');
    expect(isExpiryNonExtending(anc, dec)).toBe(true);
  });

  it('ok: descendant expires at the same time as ancestor', () => {
    const t = '2026-12-31T00:00:00.000Z';
    expect(isExpiryNonExtending(envWith([], t), envWith([], t))).toBe(true);
  });

  it('fail: descendant extends beyond ancestor', () => {
    const anc = envWith([], '2026-06-30T00:00:00.000Z');
    const dec = envWith([], '2026-12-31T00:00:00.000Z');
    expect(isExpiryNonExtending(anc, dec)).toBe(false);
  });
});
