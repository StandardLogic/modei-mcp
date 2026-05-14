# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.3] — 2026-05-14

### Fixed

- **`list_enforcement_attestations` filter enum.** Input schema for the
  `decision` filter parameter flipped from `['PERMIT', 'BLOCK',
  'SUSPEND']` (legacy enforcement-attestation vocabulary) to
  `['allow', 'block', 'request_hold']` (canonical engine-emit
  subset). The Modei API canonicalized its decision filter validator
  in v1 sprint item 1 commit 5 and now rejects the legacy values
  with a 400; any client passing the previous schema-advertised
  values was broken between commit 5 landing on the platform side
  and this release.

### Changed

- `check_gate` tool description updated to name the canonical
  authorization decisions (`allow` on grant, `block` on refusal),
  replacing the prior "allow/deny preview" wording.
- README `check_gate` row reflects the same `allow/block` wording.

### Notes

This patch is the third sibling of v1 sprint item 1 commit 6: the
`modei-typescript@1.0.0-rc.2` and `modei-python@1.1.0a2` companion
releases ship coordinated type updates for the canonical decision
taxonomy. `modei-mcp` is a passthrough MCP server — it owns no
decision vocabulary of its own; it only relays canonical wire
strings to its MCP clients. The schema-versus-API mismatch fixed
here was a forced consequence of the upstream canonicalization, not
an intentional contract change in this package.

Tracks: https://github.com/StandardLogic/modei/blob/main/specs/modei-v1-sprint.md §1

## [1.0.2] — earlier

`--help` and `--version` flag handling. See git history for details.

## [1.0.1] — earlier

Help-text API-key-prefix and `MODEI_API_URL` default fix. See git
history for details.
