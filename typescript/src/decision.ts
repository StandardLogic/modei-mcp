/**
 * Canonical decision taxonomy for the Modei runtime.
 *
 * Mirrors the eight-value taxonomy from the Modei system model §4.2.
 * The Modei API and MCP tools emit decision strings in this vocabulary
 * across `/api/gates/[id]/check`, `/api/enforce`, attestation listings,
 * verifier endpoints, and the supravision MCP server.
 *
 * Emitted in v1:
 *   - `allow`         — CEL engine grants the action.
 *   - `block`         — CEL engine refuses the action.
 *   - `request_hold`  — CEL engine holds the action pending approval.
 *   - `approved`      — supravision resolution: held action approved.
 *   - `denied`        — supravision resolution: held action denied.
 *
 * Reserved (schema admits, no runtime emit path in v1; placeholders
 * for the Output-Hold pipeline per system model §3.7):
 *   - `output_hold`   — action ran; output withheld pending review.
 *   - `released`      — reviewer released held output as-is.
 *   - `redacted`      — reviewer released held output with redactions.
 *
 * All eight values are declared in the union so consumer code typing
 * on `Decision` stays stable through the post-v1 Output-Hold rollout
 * without a propagating type-widening refactor.
 */
export type Decision =
  | 'allow'
  | 'block'
  | 'request_hold'
  | 'approved'
  | 'denied'
  | 'output_hold'
  | 'released'
  | 'redacted';

/**
 * The five decisions actually produced by the v1 runtime. Useful for
 * filter-dropdown options, exhaustive matches on currently-reachable
 * code paths, and runtime guards. The other three values from
 * `Decision` are reserved for the Output-Hold pipeline and never
 * appear in v1 responses.
 */
export const EMITTED_DECISIONS = [
  'allow',
  'block',
  'request_hold',
  'approved',
  'denied',
] as const satisfies ReadonlyArray<Decision>;

export type EmittedDecision = (typeof EMITTED_DECISIONS)[number];
