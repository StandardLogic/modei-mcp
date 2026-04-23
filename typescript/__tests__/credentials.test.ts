/**
 * AgentCredentials tests — 17 total (16 ported from Python's
 * test_credentials.py + 1 cross-SDK interop).
 *
 * POSIX-perm tests skip on Windows. File-I/O tests use a per-test tmpdir
 * that's cleaned up in afterEach.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { dirname, join } from 'node:path';
import * as util from 'node:util';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  AgentCredentials,
  CREDENTIALS_FORMAT_VERSION,
  ENV_PATH_VAR,
} from '../src/passport/credentials.js';

const WINDOWS = process.platform === 'win32';

const __filename = fileURLToPath(import.meta.url);
const FIXTURE_PATH = join(dirname(__filename), 'fixtures', 'python-written-credential.json');

interface CredentialsPayload {
  version: number;
  agent_id: string;
  public_key_base64: string;
  private_key_base64: string;
  created_at: string;
}

function validPayload(creds: AgentCredentials): CredentialsPayload {
  return {
    version: CREDENTIALS_FORMAT_VERSION,
    agent_id: creds.agentId,
    public_key_base64: Buffer.from(creds.publicKey).toString('base64'),
    private_key_base64: Buffer.from(creds.privateKey).toString('base64'),
    created_at: creds.createdAt,
  };
}

function writeFile(filePath: string, data: CredentialsPayload, mode = 0o600): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data), 'utf8');
  if (!WINDOWS) fs.chmodSync(filePath, mode);
}

let tmpDir: string;
let originalEnv: string | undefined;
let originalHome: string | undefined;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(join(os.tmpdir(), 'modei-creds-test-'));
  originalEnv = process.env[ENV_PATH_VAR];
  originalHome = process.env.HOME;
  delete process.env[ENV_PATH_VAR];
});

afterEach(() => {
  if (originalEnv === undefined) delete process.env[ENV_PATH_VAR];
  else process.env[ENV_PATH_VAR] = originalEnv;
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// 1. generate + round-trip
// ---------------------------------------------------------------------------

describe('AgentCredentials.generate', () => {
  it('creates a valid 32/32 keypair with derived agent_id', () => {
    const creds = AgentCredentials.generate();
    expect(creds.publicKey).toHaveLength(32);
    expect(creds.privateKey).toHaveLength(32);
    expect(creds.agentId.startsWith('agent_self_')).toBe(true);
    expect(creds.agentId).toHaveLength(43);
  });
});

describe('save + load round-trip', () => {
  it('preserves keys and createdAt byte-for-byte', () => {
    const p = join(tmpDir, 'creds.json');
    const original = AgentCredentials.generate();
    original.save(p);

    const loaded = AgentCredentials.load(p);
    expect(Buffer.from(loaded.publicKey).equals(Buffer.from(original.publicKey))).toBe(true);
    expect(Buffer.from(loaded.privateKey).equals(Buffer.from(original.privateKey))).toBe(true);
    expect(loaded.agentId).toBe(original.agentId);
    expect(loaded.createdAt).toBe(original.createdAt);
  });
});

// ---------------------------------------------------------------------------
// 2. loadOrCreate semantics
// ---------------------------------------------------------------------------

describe('loadOrCreate', () => {
  it('missing file creates, second call is idempotent', () => {
    const p = join(tmpDir, 'creds.json');
    expect(fs.existsSync(p)).toBe(false);
    const creds = AgentCredentials.loadOrCreate(p);
    expect(fs.existsSync(p)).toBe(true);
    const again = AgentCredentials.loadOrCreate(p);
    expect(again.agentId).toBe(creds.agentId);
  });

  it('existing file loads without regenerating', () => {
    const p = join(tmpDir, 'creds.json');
    const first = AgentCredentials.loadOrCreate(p);
    const second = AgentCredentials.loadOrCreate(p);
    expect(second.agentId).toBe(first.agentId);
    expect(Buffer.from(second.privateKey).equals(Buffer.from(first.privateKey))).toBe(true);
  });
});

describe('load missing file', () => {
  it('throws ENOENT from readFileSync', () => {
    const p = join(tmpDir, 'nope.json');
    try {
      AgentCredentials.load(p);
      throw new Error('expected load to throw');
    } catch (err) {
      expect((err as NodeJS.ErrnoException).code).toBe('ENOENT');
    }
  });
});

// ---------------------------------------------------------------------------
// 3. POSIX permissions
// ---------------------------------------------------------------------------

describe.skipIf(WINDOWS)('POSIX perms', () => {
  it('save writes file with mode 0o600', () => {
    const p = join(tmpDir, 'creds.json');
    AgentCredentials.generate().save(p);
    const mode = fs.statSync(p).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('load rejects loose perms (0o644) with message mentioning mode', () => {
    const p = join(tmpDir, 'creds.json');
    const creds = AgentCredentials.generate();
    writeFile(p, validPayload(creds), 0o644);
    expect(() => AgentCredentials.load(p)).toThrow(/0644/);
  });
});

// ---------------------------------------------------------------------------
// 4. env override + path precedence
// ---------------------------------------------------------------------------

describe('path precedence', () => {
  it('env var is used when no explicit path', () => {
    const envPath = join(tmpDir, 'via_env.json');
    process.env[ENV_PATH_VAR] = envPath;
    const creds = AgentCredentials.loadOrCreate();
    expect(fs.existsSync(envPath)).toBe(true);
    expect(AgentCredentials.load(envPath).agentId).toBe(creds.agentId);
  });

  it('explicit path overrides env var', () => {
    const envPath = join(tmpDir, 'env.json');
    const explicitPath = join(tmpDir, 'explicit.json');
    process.env[ENV_PATH_VAR] = envPath;
    AgentCredentials.loadOrCreate(explicitPath);
    expect(fs.existsSync(explicitPath)).toBe(true);
    expect(fs.existsSync(envPath)).toBe(false);
  });

  it('no path and no env throws mentioning the env var name', () => {
    delete process.env[ENV_PATH_VAR];
    expect(() => AgentCredentials.loadOrCreate()).toThrow(new RegExp(ENV_PATH_VAR));
  });
});

// ---------------------------------------------------------------------------
// 5. tamper detection + format version
// ---------------------------------------------------------------------------

describe('tamper detection', () => {
  it('rejects a file with stored agent_id not matching derived', () => {
    const p = join(tmpDir, 'creds.json');
    const creds = AgentCredentials.generate();
    const payload = validPayload(creds);
    payload.agent_id = 'agent_self_' + '0'.repeat(32);
    writeFile(p, payload, 0o600);
    expect(() => AgentCredentials.load(p)).toThrow(/agent_id mismatch/);
  });

  it('rejects an unknown format version', () => {
    const p = join(tmpDir, 'creds.json');
    const creds = AgentCredentials.generate();
    const payload = validPayload(creds);
    payload.version = 2;
    writeFile(p, payload, 0o600);
    expect(() => AgentCredentials.load(p)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// 6. leak-safe display (5 formatters × 1 test)
// ---------------------------------------------------------------------------

describe('display does not leak private key', () => {
  it('toString / util.inspect / JSON.stringify / util.format %O / util.format %o all hide privateKey', () => {
    const creds = AgentCredentials.generate();
    const privB64 = Buffer.from(creds.privateKey).toString('base64');

    const renderings = [
      creds.toString(),
      util.inspect(creds),
      JSON.stringify(creds),
      util.format('%O', creds),
      util.format('%o', creds),
    ];
    for (const r of renderings) {
      expect(r).not.toContain(privB64);
      // Also assert the agentId (public, safe) is visible in at least the
      // default rendering pair — sanity that the object isn't rendered empty.
      if (r === creds.toString() || r === util.inspect(creds)) {
        expect(r).toContain('agent_self_');
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 7. atomic save + malformed JSON + tilde
// ---------------------------------------------------------------------------

describe('atomic save', () => {
  it('does not leave a .tmp file behind on success', () => {
    const p = join(tmpDir, 'creds.json');
    AgentCredentials.generate().save(p);
    expect(fs.existsSync(p)).toBe(true);
    expect(fs.existsSync(p + '.tmp')).toBe(false);
  });
});

describe('malformed input', () => {
  it('malformed JSON throws with "not valid JSON"', () => {
    const p = join(tmpDir, 'creds.json');
    fs.writeFileSync(p, '{not json', 'utf8');
    if (!WINDOWS) fs.chmodSync(p, 0o600);
    expect(() => AgentCredentials.load(p)).toThrow(/not valid JSON/);
  });
});

describe('tilde expansion', () => {
  it('expands ~/ via HOME env var', () => {
    process.env.HOME = tmpDir;
    const creds = AgentCredentials.loadOrCreate('~/nested/creds.json');
    const resolved = join(tmpDir, 'nested', 'creds.json');
    expect(fs.existsSync(resolved)).toBe(true);
    expect(creds.agentId.startsWith('agent_self_')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 8. Cross-SDK interop: Python-written credential is loadable by TS SDK
// ---------------------------------------------------------------------------

/**
 * Cross-SDK interop: load a credential file written by the Python SDK.
 *
 * Fixture generation inputs (deterministic — regenerating with these exact
 * values produces a byte-identical fixture file):
 *
 *   seed       = b'modei-c20.3-interop-test-seed!!!'   (32 bytes, ASCII)
 *   created_at = '2026-04-22T19:30:00Z'
 *
 * Expected derived values:
 *   agent_id          = 'agent_self_A-4_q60HJGOqax9gNqzxZ48yEYCrFVX6'
 *   public_key_base64 = 'fiMzwuMFDCZhRyhItKtuxgGcP5xw9uDFznGdBWng6W8='
 *
 * Regeneration script (from the python/ directory):
 *
 *   python3 -c "
 *   from modei.passport.credentials import AgentCredentials
 *   creds = AgentCredentials(
 *       private_key_seed=b'modei-c20.3-interop-test-seed!!!',
 *       created_at='2026-04-22T19:30:00Z',
 *   )
 *   creds.save('__tests__/fixtures/python-written-credential.json')
 *   "
 *
 * Git does not preserve POSIX mode 0o600 reliably across clones (it only
 * tracks the executable bit). The test copies the fixture to a per-test
 * tmpdir and chmods 0o600 before calling load, so the interop check is
 * independent of the on-disk mode of the checked-in fixture.
 */
describe('cross-SDK interop', () => {
  it('loads a Python-written credential file and derives the expected agent_id', () => {
    const scratch = join(tmpDir, 'python-written-credential.json');
    fs.copyFileSync(FIXTURE_PATH, scratch);
    if (!WINDOWS) fs.chmodSync(scratch, 0o600);

    const creds = AgentCredentials.load(scratch);

    expect(creds.agentId).toBe('agent_self_A-4_q60HJGOqax9gNqzxZ48yEYCrFVX6');
    expect(Buffer.from(creds.publicKey).toString('base64')).toBe(
      'fiMzwuMFDCZhRyhItKtuxgGcP5xw9uDFznGdBWng6W8=',
    );
    expect(creds.publicKey).toHaveLength(32);
    expect(creds.privateKey).toHaveLength(32);
    expect(creds.createdAt).toBe('2026-04-22T19:30:00Z');

    // Regeneration contract: the private key in the fixture must be exactly
    // the deterministic seed used to generate it. If this ever fails, the
    // fixture has drifted from the documented seed.
    expect(Buffer.from(creds.privateKey).toString('utf8')).toBe(
      'modei-c20.3-interop-test-seed!!!',
    );
  });
});
