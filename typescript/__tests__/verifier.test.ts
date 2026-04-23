/**
 * PassportVerifier tests. Port of Python test_verifier.py (17 tests) minus
 * the Pydantic-specific error-structure canary, plus the cross-backend
 * delegation fixture parity test from test_delegation.py.
 *
 * Covers Spec 2 §13 rows 10–16 locally. Rows 17, 18 (platform/gate root
 * delegation) require backend key resolution and are out of scope for the
 * local verifier.
 */

import { bytesToHex } from '@noble/hashes/utils.js';
import * as ed from '@noble/ed25519';
import { describe, expect, it } from 'vitest';

import { canonicalizeStrict } from '../src/passport/canonical.js';
import { AgentCredentials } from '../src/passport/credentials.js';
import type {
  DelegationChainEntry,
  Envelope,
  PassportPermission,
} from '../src/passport/envelope.js';
import { PassportIssuer } from '../src/passport/issuer.js';
import { TrustTier } from '../src/passport/tier.js';
import { PassportVerifier } from '../src/passport/verifier.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function signEnvelopeWithSeed(env: Envelope, privSeed: Uint8Array): string {
  const sig = ed.sign(canonicalizeStrict(env), privSeed);
  return Buffer.from(sig).toString('base64');
}

async function hexSha256(pub: Uint8Array): Promise<string> {
  const { sha256 } = await import('@noble/hashes/sha2.js');
  return bytesToHex(sha256(pub));
}

function issueSelf(
  creds: AgentCredentials,
  opts: { delegationAuthority?: boolean; permissions?: PassportPermission[]; expiresAt?: Date } = {},
): { env: Envelope; sig: string } {
  const issuer = new PassportIssuer(creds, { identityClaim: 'a@example.com' });
  const { envelope, signature } = issuer.selfIssue({
    permissions: opts.permissions ?? [{ permission_key: 'api:read', constraints: {} }],
    expiresAt: opts.expiresAt ?? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    delegationAuthority: opts.delegationAuthority,
  });
  return { env: envelope, sig: signature };
}

/**
 * Build a self-rooted delegation chain of `depth` links plus a leaf.
 * Port of Python's `_build_delegate_chain_from_root`.
 */
async function buildDelegateChain(options: {
  depth: number;
  rootCreds: AgentCredentials;
  rootPermissions?: PassportPermission[];
  leafPermissions?: PassportPermission[];
  linkExpiresAt?: string;
  leafExpiresAt?: string;
  authorityMissingAtIndex?: number;
}): Promise<{ leaf: Envelope; leafSig: string; allCreds: AgentCredentials[] }> {
  const {
    depth,
    rootCreds,
    rootPermissions = [{ permission_key: 'api:read', constraints: {} }],
    leafPermissions,
    linkExpiresAt,
    leafExpiresAt,
    authorityMissingAtIndex,
  } = options;

  const now = Date.now();
  const issued = new Date(now).toISOString();
  const linkExpires = linkExpiresAt ?? new Date(now + 30 * 24 * 60 * 60 * 1000).toISOString();
  const leafExpires = leafExpiresAt ?? new Date(now + 29 * 24 * 60 * 60 * 1000).toISOString();

  const rootPubB64 = Buffer.from(rootCreds.publicKey).toString('base64');
  const rootIssuerId = 'self:' + (await hexSha256(rootCreds.publicKey));

  const root: Envelope = {
    schema_version: 2,
    passport_id: 'pp_self_root',
    identity: {
      agent_id: rootCreds.agentId,
      agent_name: 'root@example.com',
      public_key: rootPubB64,
    },
    permissions: rootPermissions,
    provenance: {
      issuer: { type: 'self', id: rootIssuerId, key_id: 'self' },
      gate_id: null,
      catalog_content_hash: null,
      catalog_version: null,
      delegation_chain: null,
      issued_at: issued,
      expires_at: linkExpires,
    },
    delegation_authority: authorityMissingAtIndex !== 0,
    verification_evidence: [],
  };
  const rootSig = signEnvelopeWithSeed(root, rootCreds.privateKey);

  const chainEntries: DelegationChainEntry[] = [{ passport_json: root, signature: rootSig }];
  const allCreds: AgentCredentials[] = [rootCreds];

  for (let i = 1; i < depth; i++) {
    const childCreds = AgentCredentials.generate();
    const childEnv: Envelope = {
      schema_version: 2,
      passport_id: `pp_self_link_${i}`,
      identity: {
        agent_id: childCreds.agentId,
        agent_name: `link${i}@example.com`,
        public_key: Buffer.from(childCreds.publicKey).toString('base64'),
      },
      permissions: rootPermissions,
      provenance: {
        issuer: { type: 'delegate', id: 'delegate:pp_self_root', key_id: 'self' },
        gate_id: null,
        catalog_content_hash: null,
        catalog_version: null,
        delegation_chain: chainEntries.slice(),
        issued_at: issued,
        expires_at: linkExpires,
      },
      delegation_authority: authorityMissingAtIndex !== i,
      verification_evidence: [],
    };
    const parentCred = allCreds[i - 1];
    if (parentCred === undefined) throw new Error('unreachable');
    const childSig = signEnvelopeWithSeed(childEnv, parentCred.privateKey);
    chainEntries.push({ passport_json: childEnv, signature: childSig });
    allCreds.push(childCreds);
  }

  const leafCreds = AgentCredentials.generate();
  const leaf: Envelope = {
    schema_version: 2,
    passport_id: 'pp_self_leaf',
    identity: {
      agent_id: leafCreds.agentId,
      agent_name: 'leaf@example.com',
      public_key: Buffer.from(leafCreds.publicKey).toString('base64'),
    },
    permissions: leafPermissions ?? rootPermissions,
    provenance: {
      issuer: { type: 'delegate', id: 'delegate:pp_self_root', key_id: 'self' },
      gate_id: null,
      catalog_content_hash: null,
      catalog_version: null,
      delegation_chain: chainEntries,
      issued_at: issued,
      expires_at: leafExpires,
    },
    delegation_authority: false,
    verification_evidence: [],
  };
  const lastCred = allCreds[allCreds.length - 1];
  if (lastCred === undefined) throw new Error('unreachable');
  const leafSig = signEnvelopeWithSeed(leaf, lastCred.privateKey);
  allCreds.push(leafCreds);
  return { leaf, leafSig, allCreds };
}

// ---------------------------------------------------------------------------
// Single-passport path
// ---------------------------------------------------------------------------

describe('PassportVerifier — single-passport path', () => {
  it('verifies a valid self-issued passport at tier L0', () => {
    const creds = AgentCredentials.generate();
    const { env, sig } = issueSelf(creds);
    const result = new PassportVerifier().verify(env, sig);
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.tier).toBe(TrustTier.L0);
  });

  it('rejects a tampered signature with reasonCode signature_invalid', () => {
    const creds = AgentCredentials.generate();
    const { env, sig } = issueSelf(creds);
    const raw = Buffer.from(sig, 'base64');
    raw[0] = (raw[0] ?? 0) ^ 0x01;
    const badSig = raw.toString('base64');
    const result = new PassportVerifier().verify(env, badSig);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reasonCode).toBe('signature_invalid');
  });

  it('rejects a tampered envelope with reasonCode signature_invalid', () => {
    const creds = AgentCredentials.generate();
    const { env, sig } = issueSelf(creds);
    const tampered: Envelope = { ...env, passport_id: env.passport_id + 'x' };
    const result = new PassportVerifier().verify(tampered, sig);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reasonCode).toBe('signature_invalid');
  });

  it('rejects an invalid envelope shape', () => {
    const result = new PassportVerifier().verify({ not: 'a valid envelope' }, 'somesig');
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reasonCode).toBe('invalid_envelope_shape');
  });

  it('rejects unsupported schema_version (peek preserves the distinction)', () => {
    const bad = {
      schema_version: 1,
      passport_id: 'pp_x',
      identity: { agent_id: 'a', agent_name: null, public_key: 'k' },
      permissions: [],
      provenance: {
        issuer: { type: 'self', id: 'self:x', key_id: 'self' },
        gate_id: null,
        catalog_content_hash: null,
        catalog_version: null,
        delegation_chain: null,
        issued_at: 't',
        expires_at: 't',
      },
      delegation_authority: false,
      verification_evidence: [],
    };
    const result = new PassportVerifier().verify(bad, 'sig');
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reasonCode).toBe('unsupported_schema_version');
  });

  it('rejects signature not in base64', () => {
    const creds = AgentCredentials.generate();
    const { env } = issueSelf(creds);
    const result = new PassportVerifier().verify(env, '!!!not-base64!!!');
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reasonCode).toBe('signature_malformed');
  });

  it('rejects signature with wrong byte length', () => {
    const creds = AgentCredentials.generate();
    const { env } = issueSelf(creds);
    const short = Buffer.alloc(32, 0x41).toString('base64'); // 32 bytes, not 64
    const result = new PassportVerifier().verify(env, short);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reasonCode).toBe('signature_malformed');
  });

  it('rejects malformed public key', () => {
    const creds = AgentCredentials.generate();
    const { env, sig } = issueSelf(creds);
    const badEnv: Envelope = {
      ...env,
      identity: { ...env.identity, public_key: '!!!not-base64!!!' },
    };
    const result = new PassportVerifier().verify(badEnv, sig);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reasonCode).toBe('public_key_malformed');
  });

  it('issuer raises envelope_too_large for oversized canonical bytes', () => {
    const creds = AgentCredentials.generate();
    const bigPerms: PassportPermission[] = Array.from({ length: 200 }, () => ({
      permission_key: 'x'.repeat(200),
      constraints: { k: 'v'.repeat(200) },
    }));
    const issuer = new PassportIssuer(creds, { identityClaim: 'x@y.z' });
    expect(() =>
      issuer.selfIssue({
        permissions: bigPerms,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      }),
    ).toThrow(/envelope_too_large/);
  });

  it("platform issuer returns signature_key_unavailable with detail mentioning 'platform'", () => {
    const envDict = {
      schema_version: 2,
      passport_id: 'pp_platform_x',
      identity: { agent_id: 'a', agent_name: 'x', public_key: 'a'.repeat(44) },
      permissions: [{ permission_key: 'api:read', constraints: {} }],
      provenance: {
        issuer: { type: 'platform', id: 'issuer:org_1', key_id: 'ik_1' },
        gate_id: null,
        catalog_content_hash: null,
        catalog_version: null,
        delegation_chain: null,
        issued_at: '2026-04-22T00:00:00.000Z',
        expires_at: '2026-05-22T00:00:00.000Z',
      },
      delegation_authority: false,
      verification_evidence: [],
    };
    const result = new PassportVerifier().verify(envDict, 'any_sig');
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reasonCode).toBe('signature_key_unavailable');
      expect(result.detail).toContain('platform');
    }
  });

  it("gate issuer returns signature_key_unavailable with detail mentioning 'gate'", () => {
    const envDict = {
      schema_version: 2,
      passport_id: 'pp_gate_x',
      identity: { agent_id: 'a', agent_name: 'x', public_key: 'a'.repeat(44) },
      permissions: [{ permission_key: 'api:read', constraints: {} }],
      provenance: {
        issuer: { type: 'gate', id: 'gate_1', key_id: 'gk_1' },
        gate_id: 'gate_1',
        catalog_content_hash: null,
        catalog_version: null,
        delegation_chain: null,
        issued_at: '2026-04-22T00:00:00.000Z',
        expires_at: '2026-05-22T00:00:00.000Z',
      },
      delegation_authority: false,
      verification_evidence: [],
    };
    const result = new PassportVerifier().verify(envDict, 'any_sig');
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reasonCode).toBe('signature_key_unavailable');
      expect(result.detail).toContain('gate');
    }
  });
});

// ---------------------------------------------------------------------------
// Delegation chain path (spec §13 rows 10–16)
// ---------------------------------------------------------------------------

describe('PassportVerifier — delegation chain path', () => {
  it('depth-1 self-rooted chain permits (row 10)', async () => {
    const rootCreds = AgentCredentials.generate();
    const { leaf, leafSig } = await buildDelegateChain({ depth: 1, rootCreds });
    const result = new PassportVerifier().verify(leaf, leafSig);
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.tier).toBe(TrustTier.L0);
  });

  it('depth-3 chain permits (row 11)', async () => {
    const rootCreds = AgentCredentials.generate();
    const { leaf, leafSig } = await buildDelegateChain({ depth: 3, rootCreds });
    const result = new PassportVerifier().verify(leaf, leafSig);
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.tier).toBe(TrustTier.L0);
  });

  it('depth-6 chain exceeds max_delegation_depth (row 12)', async () => {
    const rootCreds = AgentCredentials.generate();
    const { leaf, leafSig } = await buildDelegateChain({ depth: 6, rootCreds });
    const result = new PassportVerifier().verify(leaf, leafSig);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reasonCode).toBe('delegation_chain_too_deep');
  });

  it('middle link lacking delegation_authority is rejected (row 13)', async () => {
    const rootCreds = AgentCredentials.generate();
    const { leaf, leafSig } = await buildDelegateChain({
      depth: 3,
      rootCreds,
      authorityMissingAtIndex: 1,
    });
    const result = new PassportVerifier().verify(leaf, leafSig);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reasonCode).toBe('delegation_authority_missing');
  });

  it('permission elevation: leaf adds a permission absent from root (row 14)', async () => {
    const rootCreds = AgentCredentials.generate();
    const { leaf, leafSig } = await buildDelegateChain({
      depth: 2,
      rootCreds,
      rootPermissions: [{ permission_key: 'api:read', constraints: {} }],
      leafPermissions: [{ permission_key: 'api:write', constraints: {} }],
    });
    const result = new PassportVerifier().verify(leaf, leafSig);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reasonCode).toBe('permission_elevation_in_chain');
  });

  it('permission elevation: leaf loosens a numeric constraint (row 15)', async () => {
    const rootCreds = AgentCredentials.generate();
    const { leaf, leafSig } = await buildDelegateChain({
      depth: 2,
      rootCreds,
      rootPermissions: [{ permission_key: 'api:read', constraints: { max_per_action_cost: 100 } }],
      leafPermissions: [{ permission_key: 'api:read', constraints: { max_per_action_cost: 500 } }],
    });
    const result = new PassportVerifier().verify(leaf, leafSig);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reasonCode).toBe('permission_elevation_in_chain');
  });

  it('leaf expiry extending past ancestor is rejected (row 16)', async () => {
    const now = Date.now();
    const linkExp = new Date(now + 60 * 60 * 1000).toISOString(); // 1 hour
    const leafExp = new Date(now + 24 * 60 * 60 * 1000).toISOString(); // 24 hours
    const rootCreds = AgentCredentials.generate();
    const { leaf, leafSig } = await buildDelegateChain({
      depth: 2,
      rootCreds,
      linkExpiresAt: linkExp,
      leafExpiresAt: leafExp,
    });
    const result = new PassportVerifier().verify(leaf, leafSig);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reasonCode).toBe('expiry_extension_in_chain');
  });
});

// ---------------------------------------------------------------------------
// Cross-backend delegation fixture parity.
// ---------------------------------------------------------------------------
//
// Ground-truth constants byte-copied from
// python/tests/passport/test_delegation.py:424-504. Backend generated these
// via ~/Projects/modei/scripts/sdk_parity_fixture.ts; backend's own
// verifyPassportWithChain round-trip returned {"valid": true, "tier": "L0"}.
//
// Deterministic: root seed = 32 zero bytes; leaf seed = bytes(range(32)).
// If this test fails, STOP. Canonicalizer or signer drifted from backend
// parity — release-blocker per spec §11.2 and §13 rows 23/26.

const FX_ROOT_PUB_B64 = 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=';
const FX_ROOT_PRIV_SEED = new Uint8Array(32);
const FX_LEAF_PUB_B64 = 'A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=';
const FX_ROOT_AGENT_ID = 'agent_self_E545QOZLVJFyIIjZoNdBYo_IJuCUddNB';
const FX_LEAF_AGENT_ID = 'agent_self_Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3';
const FX_ISSUED_AT = '2026-04-22T00:00:00.000Z';
const FX_EXPIRES_AT = '2026-05-22T00:00:00.000Z';
const FX_ROOT_CANONICAL_HEX =
  '7b2264656c65676174696f6e5f617574686f72697479223a747275652c226964656e74697479223a7b226167656e745f6964223a226167656e745f73656c665f45353435514f5a4c564a467949496a5a6f4e6442596f5f494a75435564644e42222c226167656e745f6e616d65223a22726f6f74406465762e6c6f63616c222c227075626c69635f6b6579223a224f326f6e764d3632704331696f366a514b6d384e6332557946586364346b4f6d4f7342496f59745a32696b3d227d2c2270617373706f72745f6964223a2270705f73656c665f666978747572655f726f6f74222c227065726d697373696f6e73223a5b7b22636f6e73747261696e7473223a7b7d2c227065726d697373696f6e5f6b6579223a226170693a72656164227d5d2c2270726f76656e616e6365223a7b22636174616c6f675f636f6e74656e745f68617368223a6e756c6c2c22636174616c6f675f76657273696f6e223a6e756c6c2c2264656c65676174696f6e5f636861696e223a6e756c6c2c22657870697265735f6174223a22323032362d30352d32325430303a30303a30302e3030305a222c22676174655f6964223a6e756c6c2c226973737565645f6174223a22323032362d30342d32325430303a30303a30302e3030305a222c22697373756572223a7b226964223a2273656c663a31333965333934306536346235343931373232303838643961306437343136323866633832366530393437356433343161373830616364653363346238303730222c226b65795f6964223a2273656c66222c2274797065223a2273656c66227d7d2c22736368656d615f76657273696f6e223a322c22766572696669636174696f6e5f65766964656e6365223a5b5d7d';
const FX_LEAF_CANONICAL_HEX =
  '7b2264656c65676174696f6e5f617574686f72697479223a66616c73652c226964656e74697479223a7b226167656e745f6964223a226167656e745f73656c665f566b64617031526a52307743686439647679764b747a326d555457494f656d33222c226167656e745f6e616d65223a226c656166406465762e6c6f63616c222c227075626c69635f6b6579223a2241364548762f504f454c3464634e3059353076416d57666b316a436270513166486479475a424a564d62673d227d2c2270617373706f72745f6964223a2270705f64656c65676174655f666978747572655f6c656166222c227065726d697373696f6e73223a5b7b22636f6e73747261696e7473223a7b7d2c227065726d697373696f6e5f6b6579223a226170693a72656164227d5d2c2270726f76656e616e6365223a7b22636174616c6f675f636f6e74656e745f68617368223a6e756c6c2c22636174616c6f675f76657273696f6e223a6e756c6c2c2264656c65676174696f6e5f636861696e223a5b7b2270617373706f72745f6a736f6e223a7b2264656c65676174696f6e5f617574686f72697479223a747275652c226964656e74697479223a7b226167656e745f6964223a226167656e745f73656c665f45353435514f5a4c564a467949496a5a6f4e6442596f5f494a75435564644e42222c226167656e745f6e616d65223a22726f6f74406465762e6c6f63616c222c227075626c69635f6b6579223a224f326f6e764d3632704331696f366a514b6d384e6332557946586364346b4f6d4f7342496f59745a32696b3d227d2c2270617373706f72745f6964223a2270705f73656c665f666978747572655f726f6f74222c227065726d697373696f6e73223a5b7b22636f6e73747261696e7473223a7b7d2c227065726d697373696f6e5f6b6579223a226170693a72656164227d5d2c2270726f76656e616e6365223a7b22636174616c6f675f636f6e74656e745f68617368223a6e756c6c2c22636174616c6f675f76657273696f6e223a6e756c6c2c2264656c65676174696f6e5f636861696e223a6e756c6c2c22657870697265735f6174223a22323032362d30352d32325430303a30303a30302e3030305a222c22676174655f6964223a6e756c6c2c226973737565645f6174223a22323032362d30342d32325430303a30303a30302e3030305a222c22697373756572223a7b226964223a2273656c663a31333965333934306536346235343931373232303838643961306437343136323866633832366530393437356433343161373830616364653363346238303730222c226b65795f6964223a2273656c66222c2274797065223a2273656c66227d7d2c22736368656d615f76657273696f6e223a322c22766572696669636174696f6e5f65766964656e6365223a5b5d7d2c227369676e6174757265223a225044336d544957792b58716d756138346f745a4b354f48654b77742f4d67316f736b49524268334378515949495531464e355776612f524154665a3449434d544e66764a6972537053724438377439347465665342673d3d227d5d2c22657870697265735f6174223a22323032362d30352d32325430303a30303a30302e3030305a222c22676174655f6964223a6e756c6c2c226973737565645f6174223a22323032362d30342d32325430303a30303a30302e3030305a222c22697373756572223a7b226964223a2264656c65676174653a70705f73656c665f666978747572655f726f6f74222c226b65795f6964223a2273656c66222c2274797065223a2264656c6567617465227d7d2c22736368656d615f76657273696f6e223a322c22766572696669636174696f6e5f65766964656e6365223a5b5d7d';
const FX_ROOT_SIGNATURE_B64 =
  'PD3mTIWy+Xqmua84otZK5OHeKwt/Mg1oskIRBh3CxQYIIU1FN5Wva/RATfZ4ICMTNfvJirSpSrD87t94tefSBg==';
const FX_LEAF_SIGNATURE_B64 =
  'q6SVXu7fc0Qt9+IyQAib+T8W2d3veWh6PiCJLQjlJcAdfTMMzAJYd/vpOZ6p98q/crjrLa+vq9pR+Phi/YDTBQ==';

describe('cross-backend delegation fixture parity', () => {
  it('matches backend canonical bytes + signatures; verifier agrees {valid:true, tier:L0}', () => {
    const root: Envelope = {
      schema_version: 2,
      passport_id: 'pp_self_fixture_root',
      identity: {
        agent_id: FX_ROOT_AGENT_ID,
        agent_name: 'root@dev.local',
        public_key: FX_ROOT_PUB_B64,
      },
      permissions: [{ permission_key: 'api:read', constraints: {} }],
      provenance: {
        issuer: {
          type: 'self',
          id: 'self:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070',
          key_id: 'self',
        },
        gate_id: null,
        catalog_content_hash: null,
        catalog_version: null,
        delegation_chain: null,
        issued_at: FX_ISSUED_AT,
        expires_at: FX_EXPIRES_AT,
      },
      delegation_authority: true,
      verification_evidence: [],
    };

    const rootCanonical = canonicalizeStrict(root);
    expect(Buffer.from(rootCanonical).toString('hex')).toBe(FX_ROOT_CANONICAL_HEX);

    const rootSig = Buffer.from(ed.sign(rootCanonical, FX_ROOT_PRIV_SEED)).toString('base64');
    expect(rootSig).toBe(FX_ROOT_SIGNATURE_B64);

    const leaf: Envelope = {
      schema_version: 2,
      passport_id: 'pp_delegate_fixture_leaf',
      identity: {
        agent_id: FX_LEAF_AGENT_ID,
        agent_name: 'leaf@dev.local',
        public_key: FX_LEAF_PUB_B64,
      },
      permissions: [{ permission_key: 'api:read', constraints: {} }],
      provenance: {
        issuer: { type: 'delegate', id: 'delegate:pp_self_fixture_root', key_id: 'self' },
        gate_id: null,
        catalog_content_hash: null,
        catalog_version: null,
        delegation_chain: [{ passport_json: root, signature: rootSig }],
        issued_at: FX_ISSUED_AT,
        expires_at: FX_EXPIRES_AT,
      },
      delegation_authority: false,
      verification_evidence: [],
    };

    const leafCanonical = canonicalizeStrict(leaf);
    expect(Buffer.from(leafCanonical).toString('hex')).toBe(FX_LEAF_CANONICAL_HEX);

    const leafSig = Buffer.from(ed.sign(leafCanonical, FX_ROOT_PRIV_SEED)).toString('base64');
    expect(leafSig).toBe(FX_LEAF_SIGNATURE_B64);

    // SDK verifier agrees with backend's chain_verify = {valid:true, tier:L0}.
    const result = new PassportVerifier().verify(leaf, leafSig);
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.tier).toBe(TrustTier.L0);
  });
});
