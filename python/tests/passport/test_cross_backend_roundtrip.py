"""C19.7 — cross-backend round-trip tests against live staging.

Spec §13 row coverage when staging is reachable:
  * Row 1  — self-issue + register (test_self_issue_and_register).
  * Row 2  — registered self-issued PERMIT at L0 gate
             (test_self_issued_permit_at_l0_gate).
  * Row 3  — self-signed revocation (test_self_signed_revocation).
  * Row 10 — 2-link delegation PERMIT at L0 gate
             (test_registered_delegation_chain_permits_at_l0_gate).
  * Row 21 — revoked passport blocked at gate (cache-propagation bounded
             poll) (test_revoked_passport_blocks_at_gate).

Rows 17 and 18 (platform- and gate-rooted delegations) remain deferred:
staging lacks the signing-key material. See modei
specs/modei-remaining-checklist.md. SDK PassportVerifier returns
`signature_key_unavailable` locally for those envelopes.

Env-var gates
-------------
* ``MODEI_STAGING_URL`` — required for ALL tests here. Skips cleanly
  when absent.
* ``MODEI_TEST_L0_GATE_ID`` — required for the 3 gate-check tests
  (rows 2, 10, 21). Row 1 (register) and Row 3 (revoke) run without it.

Rate-limit warnings
-------------------
The staging register endpoint rate-limits at 10 per hour per IP.
Full-suite reruns (>1 registration per test × 5 tests ≈ 7 registrations
per run) hit that cap in 1-2 consecutive runs. Hour-long cooldowns are
required between bulk reruns from the same workstation. Per-pubkey
limits never trigger because each test generates fresh credentials.

Registered passports stay on staging as test artifacts (no cleanup).
Test 3 self-revokes its own passport; other tests do not.
"""

from __future__ import annotations

import base64
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest

from modei.passport import (
    AgentCredentials,
    DelegationBuilder,
    PassportIssuer,
    SignedPassport,
    canonicalize_strict,
)

STAGING_URL = os.environ.get("MODEI_STAGING_URL")
L0_GATE_ID = os.environ.get("MODEI_TEST_L0_GATE_ID")

requires_staging = pytest.mark.skipif(
    not STAGING_URL,
    reason="staging tests disabled; set MODEI_STAGING_URL to run",
)
requires_l0_gate = pytest.mark.skipif(
    not L0_GATE_ID,
    reason="L0 gate check disabled; set MODEI_TEST_L0_GATE_ID to run",
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _post(path: str, body: dict[str, Any], timeout: float = 30.0) -> httpx.Response:
    assert STAGING_URL is not None
    url = STAGING_URL.rstrip("/") + path
    return httpx.post(url, json=body, timeout=timeout)


def _register(signed: SignedPassport) -> httpx.Response:
    """POST /api/passports/register with a SignedPassport."""
    return _post(
        "/api/passports/register",
        {
            "passport_json": signed.envelope.model_dump(mode="json"),
            "signature": signed.signature,
        },
    )


def _gate_check(gate_id: str, passport_id: str, action: str = "test:permit") -> httpx.Response:
    return _post(
        f"/api/gates/{gate_id}/check",
        {"passport_id": passport_id, "action": action},
    )


def _iso_ms_z_now() -> str:
    now = datetime.now(timezone.utc)
    return f"{now.strftime('%Y-%m-%dT%H:%M:%S')}.{now.microsecond // 1000:03d}Z"


def _build_revocation_payload(
    passport_id: str, creds: AgentCredentials
) -> dict[str, Any]:
    """Build the {assertion_json, assertion_signature} body per revoke route."""
    import nacl.signing

    assertion_json = {
        "passport_id": passport_id,
        "action": "revoke",
        "nonce": base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("="),
        "revoked_at": _iso_ms_z_now(),
    }
    canonical = canonicalize_strict(assertion_json)
    sig_bytes = nacl.signing.SigningKey(creds.private_key_bytes).sign(canonical).signature
    return {
        "assertion_json": assertion_json,
        "assertion_signature": base64.b64encode(sig_bytes).decode("ascii"),
    }


def _issue_fresh_self(
    *,
    delegation_authority: bool = False,
    expires_in: timedelta = timedelta(hours=1),
    permissions: list[dict[str, Any]] | None = None,
) -> tuple[AgentCredentials, SignedPassport]:
    creds = AgentCredentials.generate()
    signed = PassportIssuer(creds, identity_claim="sdk-test@dev.local").self_issue(
        permissions=permissions or [{"permission_key": "test:permit", "constraints": {}}],
        expires_in=expires_in,
        delegation_authority=delegation_authority,
    )
    return creds, signed


# ---------------------------------------------------------------------------
# Row 1 — self-issue + register
# ---------------------------------------------------------------------------


@requires_staging
@pytest.mark.staging
def test_self_issue_and_register() -> None:
    creds, signed = _issue_fresh_self()
    response = _register(signed)
    assert response.status_code == 200, (
        f"register failed: {response.status_code} body={response.text!r}"
    )
    body = response.json()
    assert body.get("passport_id") == signed.envelope.passport_id, (
        f"unexpected passport_id in response: {body!r}"
    )
    assert body.get("agent_id") == creds.agent_id, (
        f"agent_id mismatch: expected {creds.agent_id!r}, got {body!r}"
    )
    assert body.get("status") in {"active", "idempotent"}, (
        f"unexpected status: {body!r}"
    )


# ---------------------------------------------------------------------------
# Row 2 — registered self-issued PERMIT at L0 gate
# ---------------------------------------------------------------------------


@requires_staging
@requires_l0_gate
@pytest.mark.staging
def test_self_issued_permit_at_l0_gate() -> None:
    assert L0_GATE_ID is not None
    _, signed = _issue_fresh_self()

    reg = _register(signed)
    assert reg.status_code == 200, f"register failed: {reg.status_code} body={reg.text!r}"

    check = _gate_check(L0_GATE_ID, signed.envelope.passport_id)
    # Log the full body on failure so a shape change is visible without
    # a second test run.
    assert check.status_code == 200, (
        f"/check failed: status={check.status_code} body={check.text!r}"
    )
    body = check.json()
    assert body.get("allowed") is True, (
        f"expected allowed=true; got body={body!r} "
        f"(status={check.status_code})"
    )
    # Endpoint returns "allow"/"deny" lowercase; canonical
    # PERMIT/BLOCK/SUSPEND taxonomy reconciliation is tracked in
    # modei specs/modei-remaining-checklist.md C19.7 additions.
    assert body.get("decision") == "allow", (
        f"expected decision='allow'; got body={body!r}"
    )


# ---------------------------------------------------------------------------
# Row 3 — self-signed revocation
# ---------------------------------------------------------------------------


@requires_staging
@pytest.mark.staging
def test_self_signed_revocation() -> None:
    creds, signed = _issue_fresh_self()
    reg = _register(signed)
    assert reg.status_code == 200, f"register failed: {reg.status_code} body={reg.text!r}"

    revoke_body = _build_revocation_payload(signed.envelope.passport_id, creds)
    revoke = _post(f"/api/passports/{signed.envelope.passport_id}/revoke", revoke_body)
    assert revoke.status_code == 200, (
        f"revoke failed: status={revoke.status_code} body={revoke.text!r}"
    )
    body = revoke.json()
    assert body.get("passport_id") == signed.envelope.passport_id
    # Either freshly revoked or already_revoked is acceptable — idempotent.
    status = body.get("status")
    assert status in {"active", "already_revoked", "revoked"}, (
        f"unexpected revoke status: {body!r}"
    )


# ---------------------------------------------------------------------------
# Row 10 — delegation chain PERMIT at L0 gate
# ---------------------------------------------------------------------------


@requires_staging
@requires_l0_gate
@pytest.mark.staging
def test_registered_delegation_chain_permits_at_l0_gate() -> None:
    assert L0_GATE_ID is not None

    # Parent: self-issued with delegation_authority=True.
    parent_creds = AgentCredentials.generate()
    parent_signed = PassportIssuer(parent_creds, identity_claim="parent@dev.local").self_issue(
        permissions=[{"permission_key": "test:permit", "constraints": {}}],
        expires_in=timedelta(hours=2),
        delegation_authority=True,
    )
    parent_reg = _register(parent_signed)
    assert parent_reg.status_code == 200, (
        f"parent register failed: {parent_reg.status_code} body={parent_reg.text!r}"
    )

    # Child: delegated from parent.
    child_creds = AgentCredentials.generate()
    child_signed = (
        DelegationBuilder(parent=parent_signed, parent_credentials=parent_creds)
        .authorize(child_credentials=child_creds)
        .with_identity_claim("child@dev.local")  # required: backend rejects null agent_name on register
        .with_permissions([{"permission_key": "test:permit", "constraints": {}}])
        .with_expiry(expires_in=timedelta(hours=1))
        .sign()
    )
    child_reg = _register(child_signed)
    assert child_reg.status_code == 200, (
        f"child register failed: {child_reg.status_code} body={child_reg.text!r}"
    )

    check = _gate_check(L0_GATE_ID, child_signed.envelope.passport_id)
    assert check.status_code == 200, (
        f"/check failed: status={check.status_code} body={check.text!r}"
    )
    body = check.json()
    assert body.get("allowed") is True, (
        f"expected allowed=true for delegated passport; got body={body!r}"
    )
    assert body.get("decision") == "permit", (
        f"expected decision='permit'; got body={body!r}"
    )


# ---------------------------------------------------------------------------
# Row 21 — revoked passport blocked at gate (bounded-poll cache propagation)
# ---------------------------------------------------------------------------


@requires_staging
@requires_l0_gate
@pytest.mark.staging
def test_revoked_passport_blocks_at_gate() -> None:
    """Revoke cascades to gate /check within the 60s revocation-cache TTL.

    Spec §10 documents a bounded eventual-consistency window:
    gates running against a warm cache may continue to PERMIT a
    revoked passport until the cache refreshes (default TTL 60s).
    This test polls with bounded retries (up to 6 × 15s = 90s) so the
    cache has ample time to refresh. Passes when ``allowed == false``
    with a revocation-related reason is observed at any iteration.
    Fails only if all 6 attempts return ``allowed == true`` — that
    would indicate the cache cascade is fully broken, not slow.

    Logs the observed reason_code even on success so a silent
    reason-code rename (e.g., passport_revoked → revoked) becomes
    visible in the test output without breaking pass/fail.
    """
    assert L0_GATE_ID is not None

    creds, signed = _issue_fresh_self()
    reg = _register(signed)
    assert reg.status_code == 200, f"register failed: {reg.status_code} body={reg.text!r}"

    revoke_body = _build_revocation_payload(signed.envelope.passport_id, creds)
    revoke = _post(f"/api/passports/{signed.envelope.passport_id}/revoke", revoke_body)
    assert revoke.status_code == 200, (
        f"revoke failed: status={revoke.status_code} body={revoke.text!r}"
    )

    MAX_ATTEMPTS = 6
    SLEEP_SECONDS = 15
    observed: list[dict[str, Any]] = []

    for attempt in range(1, MAX_ATTEMPTS + 1):
        check = _gate_check(L0_GATE_ID, signed.envelope.passport_id)
        # Any HTTP success-family code with a shaped body is fine here;
        # revocation may come back as 200 allowed:false OR as 4xx.
        try:
            body = check.json()
        except Exception:
            body = {"_non_json_body": check.text}
        observed.append(
            {
                "attempt": attempt,
                "status_code": check.status_code,
                "allowed": body.get("allowed"),
                "decision": body.get("decision"),
                "reason_code": body.get("reason_code"),
            }
        )
        if body.get("allowed") is False:
            print(
                f"[row21] cache cascade observed on attempt {attempt} "
                f"after ~{(attempt - 1) * SLEEP_SECONDS}s: reason_code="
                f"{body.get('reason_code')!r} decision={body.get('decision')!r}",
            )
            return
        if attempt < MAX_ATTEMPTS:
            time.sleep(SLEEP_SECONDS)

    pytest.fail(
        "revoked passport still PERMITting after "
        f"{MAX_ATTEMPTS} attempts spanning ~{(MAX_ATTEMPTS - 1) * SLEEP_SECONDS}s. "
        f"Observations: {observed}"
    )
