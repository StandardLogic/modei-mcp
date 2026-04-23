/**
 * Shared error class tree for the modei TypeScript SDK.
 *
 * `ModeiError` is the common base — introduced in C20.4 once five error
 * types justified the shared ancestor. Consumers catch `err instanceof
 * ModeiError` to distinguish SDK-emitted errors from random runtime errors.
 *
 * Hierarchy:
 *
 *   Error
 *   └── ModeiError
 *       ├── CanonicalizationError         (carries reasonCode + path)
 *       └── DelegationError
 *           ├── DelegationSubsetError     (permissionKey, dimension, …)
 *           ├── DelegationChainTooDeepError (chainLength, maxDepth)
 *           └── DelegationAuthorityMissingError
 *
 * Deliberate divergence from the Python SDK:
 * - Python has no shared base — errors are colocated with their throwers.
 *   `DelegationError` in Python extends `ValueError` so a broad
 *   `except ValueError` catches them (a Python-idiom quirk that has no TS
 *   analogue). TS consumers should use `instanceof ModeiError` instead.
 * - Field names follow C20.2 camelCase rule (`permissionKey`,
 *   `chainLength`, etc.) rather than Python's snake_case (`permission_key`).
 *
 * Contract-pin from C20.1 preserved: `CanonicalizationError` is NOT
 * `instanceof TypeError`. Validated in canonical.test.ts.
 */

export class ModeiError extends Error {
  override readonly name: string = 'ModeiError';

  constructor(message?: string) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Raised when an input cannot be RFC 8785 canonicalized.
 *
 * Migrated from `canonical.ts` in C20.4. Re-exported from `canonical.ts` for
 * path stability — existing `import { CanonicalizationError } from
 * './passport/canonical.js'` calls continue to resolve.
 */
export class CanonicalizationError extends ModeiError {
  override readonly name = 'CanonicalizationError';
  readonly reasonCode: string;
  readonly path: readonly string[];

  constructor(reasonCode: string, path: readonly string[], detail?: string) {
    const pathStr = path.length > 0 ? path.join('.') : '<root>';
    const message =
      detail !== undefined ? `${reasonCode} at ${pathStr}: ${detail}` : `${reasonCode} at ${pathStr}`;
    super(message);
    this.reasonCode = reasonCode;
    this.path = path;
  }
}

/** Base class for pre-sign delegation failures thrown by `DelegationBuilder` (C20.5). */
export class DelegationError extends ModeiError {
  override readonly name: string = 'DelegationError';
}

export interface DelegationSubsetErrorInit {
  permissionKey: string | null;
  dimension: string | null;
  ancestorValue: unknown;
  descendantValue: unknown;
  detail: string;
}

/** Child permission/constraint violates the §3.4/§3.5 subset rule. */
export class DelegationSubsetError extends DelegationError {
  override readonly name = 'DelegationSubsetError';
  readonly permissionKey: string | null;
  readonly dimension: string | null;
  readonly ancestorValue: unknown;
  readonly descendantValue: unknown;
  readonly detail: string;

  constructor(init: DelegationSubsetErrorInit) {
    super(init.detail);
    this.permissionKey = init.permissionKey;
    this.dimension = init.dimension;
    this.ancestorValue = init.ancestorValue;
    this.descendantValue = init.descendantValue;
    this.detail = init.detail;
  }
}

/** Proposed chain length exceeds spec §3.3 max of 5. */
export class DelegationChainTooDeepError extends DelegationError {
  override readonly name = 'DelegationChainTooDeepError';
  readonly chainLength: number;
  readonly maxDepth: number;

  constructor(chainLength: number, maxDepth = 5) {
    super(
      `delegation_chain_too_deep: proposed chain length ${chainLength} exceeds max ${maxDepth}`,
    );
    this.chainLength = chainLength;
    this.maxDepth = maxDepth;
  }
}

/** Parent envelope lacks `delegation_authority=true`. */
export class DelegationAuthorityMissingError extends DelegationError {
  override readonly name = 'DelegationAuthorityMissingError';

  constructor() {
    super(
      'delegation_authority_missing: parent envelope has delegation_authority=false; ' +
        'cannot delegate from it',
    );
  }
}
