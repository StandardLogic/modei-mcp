/**
 * File-backed Ed25519 agent credentials (spec §11.3).
 *
 * Node-only module — uses `node:fs`, `node:path`, `node:os`. Node ≥18 required.
 *
 * Port of the Python SDK's `modei.passport.credentials`. File-format parity
 * with that SDK is a release invariant: a credential file written by either
 * SDK MUST be loadable by the other, byte-for-byte identical for the same
 * (seed, timestamp) inputs.
 *
 * File format (v1):
 *
 * ```json
 * {
 *   "version": 1,
 *   "agent_id": "agent_self_...",
 *   "public_key_base64": "<base64 of 32-byte Ed25519 public key>",
 *   "private_key_base64": "<base64 of 32-byte Ed25519 seed>",
 *   "created_at": "<ISO 8601 UTC, seconds precision, Z suffix>"
 * }
 * ```
 *
 * Keys are sorted alphabetically and indented by 2 spaces on write — mirrors
 * Python's `json.dumps(payload, sort_keys=True, indent=2)`. Cross-SDK byte
 * equality depends on this.
 *
 * The `agent_id` field is a denormalized cache of
 * `deriveSelfAgentId(publicKey)`. On load the SDK recomputes and rejects
 * any mismatch — catches hand-edited files and gross tamper attempts.
 *
 * `private_key_base64` is the 32-byte Ed25519 seed, not an expanded private
 * key. `@noble/ed25519`'s `getPublicKey(seed)` is deterministic.
 *
 * Storage path precedence:
 * 1. Explicit `path` argument.
 * 2. `MODEI_CREDENTIALS_PATH` env var.
 * 3. No default in v1 — throws. Spec's default
 *    `$HOME/.config/modei/credentials/<agent_id>.json` is chicken-and-egg
 *    for `loadOrCreate` (agent_id doesn't exist before the key does).
 *    Deferred to v1.2.
 *
 * POSIX file perms enforced strictly: files saved with mode 0o600; loads
 * reject any looser mode. No opt-out. Windows has no equivalent; writes
 * emit a one-line warning once per process.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { z } from 'zod';

import { SELF_AGENT_ID_PREFIX, deriveSelfAgentId } from './agentId.js';

// sync SHA-512 hook for @noble/ed25519 v3; required before any sign/verify/getPublicKey call.
ed.hashes.sha512 = sha512;

export const CREDENTIALS_FORMAT_VERSION = 1;
export const ENV_PATH_VAR = 'MODEI_CREDENTIALS_PATH';
const REQUIRED_POSIX_MODE = 0o600;
const IS_WINDOWS = process.platform === 'win32';

let windowsWarningEmitted = false;
function emitWindowsWarningOnce(): void {
  if (IS_WINDOWS && !windowsWarningEmitted) {
    console.warn(
      'modei.passport.credentials: POSIX file permissions (0600) are not ' +
        'enforced on Windows. Protect credential files via filesystem ACLs ' +
        'or OS keychain (deferred to v1.2).',
    );
    windowsWarningEmitted = true;
  }
}

function expandTilde(p: string): string {
  if (p === '~') return os.homedir();
  if (p.startsWith('~/') || p.startsWith('~' + path.sep)) {
    return path.join(os.homedir(), p.slice(2));
  }
  return p;
}

function resolvePath(explicit?: string): string {
  if (explicit !== undefined) return expandTilde(explicit);
  const envPath = process.env[ENV_PATH_VAR];
  if (envPath) return expandTilde(envPath);
  throw new Error(
    `AgentCredentials: no path provided and ${ENV_PATH_VAR} is not set. ` +
      'Pass path explicitly or set the environment variable.',
  );
}

function checkPerms(filePath: string): void {
  if (IS_WINDOWS) return;
  const mode = fs.statSync(filePath).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    const modeStr = mode.toString(8).padStart(4, '0');
    throw new Error(`credentials file ${filePath} has mode ${modeStr}; require 0600`);
  }
}

function utcNowNoMillis(): string {
  // Match Python's `datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")`
  // exactly. Node's `toISOString()` includes milliseconds; strip them so
  // a TS-written file and a Python-written file with the same instant are
  // byte-identical.
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

const credentialsFileSchema = z
  .object({
    version: z.literal(CREDENTIALS_FORMAT_VERSION),
    agent_id: z.string().startsWith(SELF_AGENT_ID_PREFIX),
    public_key_base64: z.string(),
    private_key_base64: z.string(),
    created_at: z.string(),
  })
  .strict();

export interface AgentCredentialsInit {
  privateKeySeed: Uint8Array;
  createdAt?: string;
}

/**
 * Ed25519 keypair with file-backed storage.
 *
 * Construction via `new AgentCredentials({ ... })` takes raw key material
 * for internal use; public callers should prefer `generate()`, `load()`, or
 * `loadOrCreate()`.
 */
export class AgentCredentials {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
  readonly createdAt: string;

  constructor(init: AgentCredentialsInit) {
    if (init.privateKeySeed.length !== 32) {
      throw new Error(
        `privateKeySeed must be exactly 32 bytes, got ${init.privateKeySeed.length}`,
      );
    }
    this.privateKey = init.privateKeySeed;
    this.publicKey = ed.getPublicKey(init.privateKeySeed);
    this.createdAt = init.createdAt ?? utcNowNoMillis();
  }

  /** Derived `agent_self_…` id. Never stored as authoritative. */
  get agentId(): string {
    return deriveSelfAgentId(this.publicKey);
  }

  // ---- leak-safe display ----------------------------------------------------

  toString(): string {
    return `AgentCredentials { agentId: '${this.agentId}' }`;
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }

  toJSON(): { agentId: string } {
    return { agentId: this.agentId };
  }

  // ---- construction ---------------------------------------------------------

  static generate(): AgentCredentials {
    return new AgentCredentials({ privateKeySeed: ed.utils.randomSecretKey() });
  }

  static load(filePath?: string): AgentCredentials {
    const resolved = resolvePath(filePath);
    // Native ENOENT propagates from readFileSync when the file is missing —
    // matches Python's FileNotFoundError distinguishability.
    const raw = fs.readFileSync(resolved, 'utf8');
    checkPerms(resolved);

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new Error(`credentials file is not valid JSON: ${resolved}`, { cause: err });
    }

    const result = credentialsFileSchema.safeParse(parsed);
    if (!result.success) {
      throw new Error(
        `credentials file has invalid shape at ${resolved}: ${result.error.message}`,
      );
    }
    const data = result.data;

    if (data.version !== CREDENTIALS_FORMAT_VERSION) {
      throw new Error(
        `unsupported credentials format version: ${String(data.version)} ` +
          `(expected ${String(CREDENTIALS_FORMAT_VERSION)})`,
      );
    }

    let seed: Uint8Array;
    try {
      seed = new Uint8Array(Buffer.from(data.private_key_base64, 'base64'));
    } catch (err) {
      throw new Error('private_key_base64 is not valid base64', { cause: err });
    }
    if (seed.length !== 32) {
      throw new Error(
        `private_key_base64 decodes to ${seed.length} bytes, require 32`,
      );
    }

    const creds = new AgentCredentials({ privateKeySeed: seed, createdAt: data.created_at });

    // Tamper check 1: stored pubkey must match the one derived from the seed.
    const expectedPubkeyB64 = Buffer.from(creds.publicKey).toString('base64');
    if (data.public_key_base64 !== expectedPubkeyB64) {
      throw new Error(
        'public_key_base64 in file does not match key derived from ' +
          'private_key_base64 (file may be corrupt or tampered)',
      );
    }
    // Tamper check 2: stored agent_id must match the one derived from the pubkey.
    if (data.agent_id !== creds.agentId) {
      throw new Error(
        `agent_id mismatch in credentials file: stored '${data.agent_id}', ` +
          `derived '${creds.agentId}'`,
      );
    }

    return creds;
  }

  static loadOrCreate(filePath?: string): AgentCredentials {
    const resolved = resolvePath(filePath);
    if (fs.existsSync(resolved)) return AgentCredentials.load(resolved);
    const creds = AgentCredentials.generate();
    creds.save(resolved);
    return creds;
  }

  // ---- persistence ----------------------------------------------------------

  save(filePath?: string): void {
    const resolved = resolvePath(filePath);
    fs.mkdirSync(path.dirname(resolved), { recursive: true });

    const payload: Record<string, unknown> = {
      version: CREDENTIALS_FORMAT_VERSION,
      agent_id: this.agentId,
      public_key_base64: Buffer.from(this.publicKey).toString('base64'),
      private_key_base64: Buffer.from(this.privateKey).toString('base64'),
      created_at: this.createdAt,
    };
    // Match Python's `sort_keys=True`: sort keys lexicographically before
    // JSON.stringify so both SDKs emit byte-identical output.
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(payload).sort()) {
      sorted[key] = payload[key];
    }
    const serialized = JSON.stringify(sorted, null, 2);

    const tmp = resolved + '.tmp';
    try {
      // Create the tmp file with restrictive mode from the start on POSIX.
      // umask may clip the create-mode; chmodSync below is authoritative.
      fs.writeFileSync(tmp, serialized, { mode: REQUIRED_POSIX_MODE, flag: 'w', encoding: 'utf8' });
      if (!IS_WINDOWS) {
        fs.chmodSync(tmp, REQUIRED_POSIX_MODE);
      } else {
        emitWindowsWarningOnce();
      }
      // POSIX rename is atomic within a filesystem. NTFS MoveFileEx with
      // MOVEFILE_REPLACE_EXISTING is also atomic on same-volume moves.
      fs.renameSync(tmp, resolved);
    } catch (err) {
      try {
        fs.unlinkSync(tmp);
      } catch {
        // best-effort cleanup; ignore ENOENT
      }
      throw err;
    }
  }
}
