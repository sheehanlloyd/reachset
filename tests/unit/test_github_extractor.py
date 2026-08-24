"""GitHub extractor over the committed fixtures, including malformed input.

The GitHub connector has no live tenant to check it against, so the extractor
carries the whole correctness burden: every field it reads is asserted here,
and every payload shape it refuses is asserted too. Silence on a malformed
payload would mean silently understating what a credential reaches.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from reachset.connectors.github import extractor
from reachset.models import Capability, CredentialKind, PrincipalKind
from reachset.records import GrantRecord

FIXTURES = Path(__file__).parent.parent / "fixtures" / "github"


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


# --------------------------------------------------------------- timestamps


def test_timestamp_parsing_accepts_both_shapes() -> None:
    # The audit log uses epoch millis; everything else uses ISO-8601.
    assert extractor._ts(1786356000000) == datetime(2026, 8, 10, 10, 0, tzinfo=UTC)
    assert extractor._ts("2026-02-14T07:00:00Z") == datetime(2026, 2, 14, 7, 0, tzinfo=UTC)
    assert extractor._ts(None) is None
    assert extractor._ts("") is None


def test_timestamp_parsing_rejects_junk() -> None:
    with pytest.raises(ValueError, match="unparseable github timestamp"):
        extractor._ts(["not", "a", "date"])


# ------------------------------------------------------------------ members


def test_members_classify_bots_as_agents() -> None:
    records = extractor.extract_members(_load("members.json"))
    by_id = {r.external_id: r for r in records}
    assert by_id["user:501"].kind is PrincipalKind.HUMAN
    assert by_id["user:601"].kind is PrincipalKind.AGENT  # type == "Bot"


def test_member_detail_carries_name_and_email() -> None:
    (record,) = extractor.extract_members([_load("user_mkraft.json")])
    assert record.display_name == "Mira Kraft"
    assert record.email == "mira.kraft@acme.io"
    assert record.created_at == datetime(2019, 3, 12, 8, 0, tzinfo=UTC)


def test_member_without_email_keeps_none_rather_than_empty_string() -> None:
    """A null email must stay null: "" would collide with every other blank in
    the identity linker."""
    (record,) = extractor.extract_members([_load("user_dwu.json")])
    assert record.email is None
    assert record.display_name == "Dana Wu"


def test_member_falls_back_to_login_when_unnamed() -> None:
    (record,) = extractor.extract_members([{"login": "nameless", "id": 900, "type": "User"}])
    assert record.display_name == "nameless"


def test_member_without_login_is_rejected() -> None:
    with pytest.raises(ValueError, match="member entry without login"):
        extractor.extract_members([{"id": 900, "type": "User"}])


def test_member_without_id_is_rejected() -> None:
    """A member's external_id must always be the numeric id, matching every
    other extractor in this module (collaborators, deploy keys) - a login-
    keyed fallback here would silently split one person into two principals
    (user:502 as a collaborator, user:jortega as a member) instead of raising."""
    with pytest.raises(ValueError, match="member 'legacy' without id"):
        extractor.extract_members([{"login": "legacy", "type": "User"}])


# -------------------------------------------------------------------- repos


def test_repo_sensitivity_heuristic() -> None:
    records = extractor.extract_repos(_load("repos.json"))
    by_path = {r.path: r.sensitivity for r in records}
    assert by_path["acme/prod-infra"] == 3  # name hints production
    assert by_path["acme/payments-api"] == 3
    assert by_path["acme/data-tools"] == 2  # private
    assert by_path["acme/website"] == 1  # public


def test_repo_without_full_name_is_rejected() -> None:
    with pytest.raises(ValueError, match="repo entry without full_name"):
        extractor.extract_repos([{"id": 1, "private": True}])


def test_repo_without_id_uses_full_name_as_identity() -> None:
    (record,) = extractor.extract_repos([{"full_name": "acme/x", "private": False}])
    assert record.external_id == "acme/x"


# ------------------------------------------------------------ installations


def test_installations_become_app_principals_with_grants() -> None:
    payload = _load("installations.json")
    payload["org"] = "acme"
    principals, grants = extractor.extract_installations(payload)

    kinds = {p.external_id: p.kind for p in principals}
    assert kinds["installation:41"] is PrincipalKind.APP
    assert kinds["installation:42"] is PrincipalKind.APP

    by_principal = {g.principal_external_id: g for g in grants}
    # repository_selection "all" resolves to an org-wide glob...
    assert by_principal["installation:42"].resource_selector == "acme/*"
    # ...while "selected" defers to the connector's repository lookup.
    assert by_principal["installation:41"].resource_selector == "__selected__"
    assert Capability.WRITE in by_principal["installation:41"].capabilities


def test_installation_payload_missing_the_list_is_rejected() -> None:
    with pytest.raises(ValueError, match="missing 'installations'"):
        extractor.extract_installations({"total_count": 0})


def test_installation_without_app_slug_is_rejected() -> None:
    with pytest.raises(ValueError, match="installation without app_slug"):
        extractor.extract_installations({"installations": [{"id": 1, "permissions": {}}]})


def test_installation_with_no_effective_permissions_yields_no_grant() -> None:
    """`metadata: read` alone is not reach worth recording."""
    principals, grants = extractor.extract_installations(
        {"installations": [{"id": 7, "app_slug": "noop", "permissions": {}}]}
    )
    assert len(principals) == 1
    assert grants == []


def test_installation_permission_values_that_are_not_strings_are_ignored() -> None:
    caps = extractor._caps_for_permission_map({"contents": "read", "weird": True})
    assert caps == frozenset({Capability.READ})


def test_expand_selected_grant_fans_out_per_repository() -> None:
    template = GrantRecord(
        principal_external_id="installation:41",
        resource_selector="__selected__",
        scope_raw="installation:contents=write",
        capabilities=frozenset({Capability.WRITE}),
    )
    expanded = extractor.expand_selected_grant(
        template, _load("installation_41_repos.json")["repositories"]
    )
    assert {g.resource_selector for g in expanded} == {"acme/prod-infra", "acme/website"}


def test_expand_selected_grant_rejects_a_repo_without_full_name() -> None:
    template = GrantRecord(
        principal_external_id="installation:41",
        resource_selector="__selected__",
        scope_raw="x",
        capabilities=frozenset({Capability.READ}),
    )
    with pytest.raises(ValueError, match="selected repository without full_name"):
        extractor.expand_selected_grant(template, [{"id": 1}])


# --------------------------------------------------------------------- PATs


def test_pat_grants_carry_credentials_and_selection() -> None:
    payload = _load("pats.json")
    for pat in payload:
        pat["org"] = "acme"
    _, credentials, grants = extractor.extract_pat_grants(payload)

    assert {c.kind for c in credentials} == {CredentialKind.PAT}
    by_owner = {g.principal_external_id: g for g in grants}
    assert by_owner["user:501"].resource_selector == "acme/*"  # selection "all"
    assert by_owner["user:503"].resource_selector == "__selected__"  # "subset"
    assert by_owner["user:501"].credential_external_id == "pat:7101"

    expiring = next(c for c in credentials if c.external_id == "pat:7101")
    assert expiring.expires_at == datetime(2026, 12, 1, 10, 0, tzinfo=UTC)
    assert expiring.last_used_at is not None
    # A PAT with no expiry is a standing credential; it must not be invented.
    never = next(c for c in credentials if c.external_id == "pat:7102")
    assert never.expires_at is None


def test_pat_without_owner_is_rejected() -> None:
    with pytest.raises(ValueError, match="PAT grant without owner"):
        extractor.extract_pat_grants([{"id": 1, "permissions": {}}])


def test_pat_with_no_repository_reach_is_skipped() -> None:
    _, credentials, grants = extractor.extract_pat_grants(
        [{"id": 1, "owner": {"login": "a", "id": 1}, "permissions": {}, "org": "acme"}]
    )
    assert len(credentials) == 1  # the credential still exists and is tracked
    assert grants == []


def test_pat_scoped_to_no_repositories_records_no_repository_grant() -> None:
    _, _, grants = extractor.extract_pat_grants(
        [
            {
                "id": 2,
                "owner": {"login": "a", "id": 1},
                "repository_selection": "none",
                "permissions": {"organization": {"members": "read"}},
                "org": "acme",
            }
        ]
    )
    assert grants == []


def test_pat_with_an_unknown_selection_fails_loudly() -> None:
    """A selection mode we do not understand could mean anything; guessing
    would either overstate or understate reach."""
    with pytest.raises(ValueError, match="unknown PAT repository_selection"):
        extractor.extract_pat_grants(
            [
                {
                    "id": 3,
                    "owner": {"login": "a", "id": 1},
                    "repository_selection": "some-new-mode",
                    "permissions": {"repository": {"contents": "read"}},
                    "org": "acme",
                }
            ]
        )


# ------------------------------------------------------------- deploy keys


def test_deploy_keys_become_service_principals() -> None:
    principals, credentials, grants = extractor.extract_deploy_keys(
        "acme/prod-infra", _load("keys_prod_infra.json")
    )
    (principal,) = principals
    assert principal.kind is PrincipalKind.SERVICE
    assert principal.display_name == "legacy-deploy@prod"
    assert credentials[0].kind is CredentialKind.SSH_KEY
    # read_only false -> read/write on exactly the one repo
    assert grants[0].resource_selector == "acme/prod-infra"
    assert Capability.WRITE in grants[0].capabilities


def test_read_only_deploy_key_is_read_only() -> None:
    _, _, grants = extractor.extract_deploy_keys("acme/website", _load("keys_website.json"))
    assert grants[0].capabilities == frozenset({Capability.READ})


def test_deploy_key_without_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="deploy key without id"):
        extractor.extract_deploy_keys("acme/x", [{"title": "orphan"}])


def test_untitled_deploy_key_gets_a_derived_name() -> None:
    principals, _, _ = extractor.extract_deploy_keys("acme/x", [{"id": 5, "read_only": True}])
    assert principals[0].display_name == "deploy key 5"


# ------------------------------------------------------------ collaborators


def test_collaborator_roles_map_to_capabilities() -> None:
    principals, grants = extractor.extract_collaborators(
        "acme/prod-infra", _load("collab_prod_infra.json")
    )
    by_principal = {g.principal_external_id: g for g in grants}
    assert Capability.ADMIN in by_principal["user:501"].capabilities  # admin role
    assert by_principal["user:502"].capabilities == frozenset(
        {Capability.READ, Capability.WRITE}
    )  # push role
    assert {p.external_id for p in principals} == {"user:501", "user:502", "user:601"}


def test_collaborator_without_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="collaborator without id"):
        extractor.extract_collaborators("acme/x", [{"login": "ghost"}])


def test_collaborator_without_role_is_rejected() -> None:
    """No role means no way to know what they can do; refusing beats assuming
    the least-privileged reading."""
    with pytest.raises(ValueError, match="without role_name"):
        extractor.extract_collaborators("acme/x", [{"id": 1, "login": "ghost"}])


# --------------------------------------------------------------- audit log


def test_audit_log_extraction() -> None:
    events = extractor.extract_audit_log(_load("audit_page1.json")["entries"])
    assert len(events) == 3
    clone = next(e for e in events if e.action == "github.git.clone")
    assert clone.actor_external_id == "user:601"
    assert clone.target_resource_external_id == "repo:8001"
    assert clone.ip == "198.51.100.23"
    assert clone.ts == datetime(2026, 8, 10, 11, 0, tzinfo=UTC)


def test_audit_entries_without_a_repo_have_no_target() -> None:
    events = extractor.extract_audit_log(_load("audit_page2.json")["entries"])
    cancelled = next(e for e in events if "request_cancelled" in e.action)
    assert cancelled.target_resource_external_id is None


def test_audit_raw_ref_is_a_stable_content_hash() -> None:
    entries = _load("audit_page1.json")["entries"]
    first = extractor.extract_audit_log(entries)
    second = extractor.extract_audit_log(entries)
    assert [e.raw_ref for e in first] == [e.raw_ref for e in second]
    assert len({e.raw_ref for e in first}) == len(first)


def test_audit_entry_missing_required_fields_is_rejected() -> None:
    with pytest.raises(ValueError, match="missing action/timestamp"):
        extractor.extract_audit_log([{"actor": "someone"}])


def test_audit_entry_without_an_actor_is_kept_unattributed() -> None:
    """System-generated entries have no actor; dropping them would lose the
    event entirely."""
    (event,) = extractor.extract_audit_log(
        [{"@timestamp": 1786356000000, "action": "org.config_change"}]
    )
    assert event.actor_external_id is None
