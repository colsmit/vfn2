import json
import re
import sys
from argparse import Namespace
from pathlib import Path

import pytest

from binary_agent import adjudication as adjudication_module
from binary_agent import adjudication_certificates as checker_module
from binary_agent.adjudication import sha256_file
from binary_agent.adjudication_investigation import (
    ExternalCommandInvestigationProvider,
    InvestigationError,
    PACK_KIND,
    PROPOSAL_KIND,
    build_investigation_pack,
    check_investigation_pack,
    run_investigation_stage,
    run_provider_attempt,
)
from binary_agent.adjudication_verifier import (
    VerificationError,
    split_c_statements,
    verify_investigation_proposal,
)
from tests.test_adjudication_autoprove import (
    _add_source_reference_mapping,
    _elf_with_calls,
    _manifest,
    _prepare,
    _state,
)
from scripts import llm_adjudication_provider


def _source_bound_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    vulnerability_type: str = "null_pointer_dereference",
) -> tuple[Path, Path, str]:
    state = _state(
        "holdout-candidate",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type=vulnerability_type,
    )
    root = _prepare(tmp_path, [state], _elf_with_calls(), manifest_payload=_manifest([state]))
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    source_path = source_root / "worker.c"
    source_path.write_text(
        "#include <stdlib.h>\n"
        "\n"
        "static void helper(void) {\n"
        "    /* a brace in a comment: } */\n"
        "}\n"
        "\n"
        "static void target(void)\n"
        "{\n"
        "    const char *text = \"not a brace: }\";\n"
        "    char *item = calloc(1, 4);\n"
        "    item[0] = text[0];\n"
        "}\n"
    )
    sdk_hash = _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(
        adjudication_module,
        "OPENWRT_24_10_4_X86_64_SDK_SHA256",
        sdk_hash,
    )
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "target", "path": "demo/worker.c", "line": 11}
        ],
    )
    return root, source_path, state["candidate_id"]


def _proposal(candidate_id: str) -> dict:
    return {
        "schema_version": 1,
        "artifact_kind": PROPOSAL_KIND,
        "candidate_id": candidate_id,
        "proposed_decision": "escalate",
        "claim_kind": "null_path",
        "exact_operation": {"address": "0x100120", "pcode": "STORE"},
        "path_steps": [],
        "claims": {},
        "root_cause": {},
        "nearby_defects": [],
    }


def _null_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    body_lines: list[str],
    candidate_body_line: int,
) -> tuple[Path, Path, Path, dict]:
    state = _state(
        "null-holdout",
        operation_offset=0x120,
        successor_literal=False,
        vulnerability_type="null_pointer_dereference",
    )
    manifest = _manifest([state])
    manifest["entry_surfaces"] = [
        {
            "kind": "registered_callback",
            "function_address": state["location"]["address"],
            "name": "renamed_worker",
        }
    ]
    root = _prepare(tmp_path, [state], _elf_with_calls(), manifest_payload=manifest)
    source_root = root / "sources" / "demo"
    source_root.mkdir(parents=True)
    prefix = [
        "#include <stdlib.h>",
        "#include <string.h>",
        "",
        "struct record { int flag; char copy[8]; };",
        "",
        "static void renamed_worker(void)",
        "{",
    ]
    suffix = ["}"]
    source_path = source_root / "renamed.c"
    source_path.write_text("\n".join([*prefix, *body_lines, *suffix]) + "\n")
    source_line = len(prefix) + candidate_body_line
    sdk_hash = _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "OPENWRT_24_10_4_X86_64_SDK_SHA256", sdk_hash)
    monkeypatch.setattr(
        checker_module,
        "_addr2line_frames",
        lambda _reference, _address: [
            {"function": "renamed_worker", "path": "demo/renamed.c", "line": source_line}
        ],
    )
    pack_path = build_investigation_pack(root, state["candidate_id"], root / "investigation" / "packs")
    pack = json.loads(pack_path.read_text())
    return root, source_path, pack_path, pack


def _write_null_proposal(
    root: Path,
    pack: dict,
    *,
    decision: str,
    pointer: str = "fresh",
) -> Path:
    operation = pack["exact_operation"]
    proposal = {
        "schema_version": 1,
        "artifact_kind": PROPOSAL_KIND,
        "candidate_id": pack["candidate_id"],
        "proposed_decision": decision,
        "claim_kind": "null_path",
        "exact_operation": {"address": operation["address"], "pcode": operation["pcode"]},
        "path_steps": [],
        "claims": {"pointer": pointer},
        "root_cause": {},
        "nearby_defects": [],
    }
    path = root / "investigation" / f"proposal-{decision}.json"
    path.write_text(json.dumps(proposal, indent=2, sort_keys=True) + "\n")
    return path


def _spatial_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    guarded: bool = False,
) -> tuple[Path, list[Path], list[dict]]:
    states = [
        _state(
            "shifted-store-a",
            operation_offset=0x120,
            successor_literal=False,
            vulnerability_type="out_of_bounds_write",
        ),
        _state(
            "shifted-store-b",
            operation_offset=0x140,
            successor_literal=False,
            vulnerability_type="out_of_bounds_write",
        ),
    ]
    manifest = _manifest(states)
    manifest["functions"][0]["pcode_stores"][0]["write_width"] = 2
    manifest["functions"][0]["pcode_stores"][1]["write_width"] = 1
    manifest["entry_surfaces"] = [
        {
            "kind": "registered_callback",
            "function_address": states[0]["location"]["address"],
            "name": "renamed_append",
        }
    ]
    root = _prepare(tmp_path, states, _elf_with_calls(), manifest_payload=manifest)
    source_root = root / "sources" / "shifted"
    source_root.mkdir(parents=True)
    guard_lines = (
        [
            "    if ((size_t)(cursor - storage) + 2 > sizeof(storage))",
            "        return;",
        ]
        if guarded
        else []
    )
    lines = [
        "#include <stddef.h>",
        "#include <stdlib.h>",
        "",
        "static void renamed_append(const char *request_path)",
        "{",
        "    static char storage[16];",
        "    char *cursor;",
        "    if (!realpath(request_path, storage))",
        "        return;",
        "    cursor = storage + strlen(storage);",
        *guard_lines,
        "    if (cursor[-1] != '/') {",
        "        cursor[0] = '/';",
        "        cursor[1] = 0;",
        "        cursor++;",
        "    }",
        "}",
    ]
    source_path = source_root / "renamed.c"
    source_path.write_text("\n".join(lines) + "\n")
    first_line = lines.index("        cursor[0] = '/';") + 1
    second_line = lines.index("        cursor[1] = 0;") + 1
    line_by_address = {
        "0x120": first_line,
        "0x140": second_line,
    }
    sdk_hash = _add_source_reference_mapping(root, source_root)
    monkeypatch.setattr(checker_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "_git_head", lambda _root: "a" * 40)
    monkeypatch.setattr(adjudication_module, "OPENWRT_24_10_4_X86_64_SDK_SHA256", sdk_hash)

    def frames(_reference: Path, address: int) -> list[dict]:
        return [
            {
                "function": "renamed_append",
                "path": "shifted/renamed.c",
                "line": line_by_address[hex(address).lower()],
            }
        ]

    monkeypatch.setattr(checker_module, "_addr2line_frames", frames)
    pack_paths = [
        build_investigation_pack(root, state["candidate_id"], root / "investigation" / "packs")
        for state in states
    ]
    packs = [json.loads(path.read_text()) for path in pack_paths]
    return root, pack_paths, packs


def _write_spatial_proposal(root: Path, pack: dict, decision: str) -> Path:
    proposal = {
        "schema_version": 1,
        "artifact_kind": PROPOSAL_KIND,
        "candidate_id": pack["candidate_id"],
        "proposed_decision": decision,
        "claim_kind": "spatial_path",
        "exact_operation": {
            "address": pack["exact_operation"]["address"],
            "pcode": pack["exact_operation"]["pcode"],
        },
        "path_steps": [],
        "claims": {"pointer": "cursor"},
        "root_cause": {},
        "nearby_defects": [],
    }
    path = root / "investigation" / f"spatial-{pack['candidate_id']}-{decision}.json"
    path.write_text(json.dumps(proposal, indent=2, sort_keys=True) + "\n")
    return path


def test_investigation_pack_is_label_free_deterministic_and_checked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, source_path, candidate_id = _source_bound_campaign(tmp_path, monkeypatch)

    first = build_investigation_pack(root, candidate_id, root / "investigation" / "packs-a")
    second = build_investigation_pack(root, candidate_id, root / "investigation" / "packs-b")

    assert first.read_bytes() == second.read_bytes()
    pack = check_investigation_pack(root, first)
    assert pack["artifact_kind"] == PACK_KIND
    assert pack["candidate_id"] == candidate_id
    assert "expected_decision" not in json.dumps(pack)
    assert "static void target" in pack["source_context"]["function_text"]
    assert "static void helper" not in pack["source_context"]["function_text"]
    assert pack["source_context"]["sha256"] == sha256_file(source_path)
    assert len(pack["input_refs"]) == 7


def test_investigation_pack_check_rejects_changed_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, source_path, candidate_id = _source_bound_campaign(tmp_path, monkeypatch)
    pack = build_investigation_pack(root, candidate_id, root / "investigation" / "packs")
    source_path.write_text(source_path.read_text() + "\n/* changed */\n")

    with pytest.raises(InvestigationError, match="differs from frozen evidence"):
        check_investigation_pack(root, pack)


def test_external_provider_round_trip_records_hashed_provenance(tmp_path: Path) -> None:
    script = tmp_path / "provider.py"
    script.write_text(
        "import json, os, sys\n"
        "pack = json.load(sys.stdin)\n"
        "json.dump({\n"
        " 'schema_version': 1,\n"
        f" 'artifact_kind': {PROPOSAL_KIND!r},\n"
        " 'candidate_id': pack['candidate_id'],\n"
        " 'proposed_decision': 'escalate',\n"
        " 'claim_kind': 'unresolved',\n"
        " 'exact_operation': pack['exact_operation'],\n"
        " 'path_steps': [], 'claims': {}, 'root_cause': {}, 'nearby_defects': [],\n"
        " 'tier_seen': os.environ['BINARY_AGENT_ADJUDICATION_TIER'],\n"
        "}, sys.stdout)\n"
    )
    provider = ExternalCommandInvestigationProvider([sys.executable, str(script)])

    result = provider.investigate({"candidate_id": "candidate-a", "exact_operation": {}}, tier="agent")

    assert result["candidate_id"] == "candidate-a"
    assert result["tier_seen"] == "agent"
    metadata = result["_provider_metadata"]
    assert metadata["tier"] == "agent"
    assert metadata["exit_status"] == 0
    assert metadata["command_executable"]["path"] == str(Path(sys.executable).resolve())
    assert len(metadata["stdout_sha256"]) == 64
    assert len(metadata["stderr_sha256"]) == 64


def test_external_provider_timeout_and_invalid_json_are_errors(tmp_path: Path) -> None:
    slow = tmp_path / "slow.py"
    slow.write_text("import time; time.sleep(2)\n")
    malformed = tmp_path / "malformed.py"
    malformed.write_text("print('not json')\n")

    with pytest.raises(InvestigationError, match="timed out"):
        ExternalCommandInvestigationProvider(
            [sys.executable, str(slow)], timeout_seconds=0.01
        ).investigate({}, tier="direct")
    with pytest.raises(InvestigationError, match="invalid JSON"):
        ExternalCommandInvestigationProvider(
            [sys.executable, str(malformed)]
        ).investigate({}, tier="direct")


def test_provider_proposal_is_persisted_but_not_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _source_path, candidate_id = _source_bound_campaign(tmp_path, monkeypatch)
    pack = build_investigation_pack(root, candidate_id, root / "investigation" / "packs")

    class FixtureProvider:
        def investigate(self, _pack: dict, *, tier: str) -> dict:
            assert tier == "direct"
            return _proposal(candidate_id)

    attempt = run_provider_attempt(
        root,
        pack,
        FixtureProvider(),
        tier="direct",
        output_dir=root / "investigation" / "attempts",
    )

    assert attempt.status == "proposed"
    assert attempt.proposal_sha256
    assert (root / attempt.proposal_path).is_file()
    assert not (root / "reviews").exists()


def test_provider_cannot_switch_candidate_or_emit_freeform_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _source_path, candidate_id = _source_bound_campaign(tmp_path, monkeypatch)
    pack = build_investigation_pack(root, candidate_id, root / "investigation" / "packs")

    class WrongProvider:
        def investigate(self, _pack: dict, *, tier: str) -> dict:
            proposal = _proposal("another-candidate")
            proposal["proposed_decision"] = "probably safe"
            return proposal

    attempt = run_provider_attempt(
        root,
        pack,
        WrongProvider(),
        tier="direct",
        output_dir=root / "investigation" / "attempts",
    )

    assert attempt.status == "error"
    assert "candidate does not match" in attempt.error
    assert not (root / "reviews").exists()


def test_direct_llm_provider_uses_only_bounded_pack_and_records_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = {"candidate_id": "bounded-candidate", "source_context": {"function_text": "f(){}"}}
    proposal = _proposal("bounded-candidate")
    response = {
        "model": "test-model",
        "choices": [{"message": {"content": json.dumps(proposal)}}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
    }
    observed = {}

    def fake_post(url: str, key: str, payload: dict, timeout: float) -> tuple[dict, float]:
        observed.update({"url": url, "key": key, "payload": payload, "timeout": timeout})
        return response, 0.25

    monkeypatch.setattr(llm_adjudication_provider, "resolve_api_key", lambda *_args, **_kwargs: "secret")
    monkeypatch.setattr(llm_adjudication_provider, "post_chat_completion", fake_post)
    args = Namespace(
        model="test-model",
        temperature=0.0,
        max_tokens=2048,
        url="https://llm.invalid/v1",
        api_key_file=None,
        api_key_env="TEST_KEY",
        timeout_seconds=12.0,
    )

    result = llm_adjudication_provider.run(pack, args)

    assert observed["key"] == "secret"
    assert observed["url"] == "https://llm.invalid/v1/chat/completions"
    assert observed["timeout"] == 12.0
    user_message = observed["payload"]["messages"][1]["content"]
    assert json.loads(user_message) == {"investigation_pack": pack}
    assert result["candidate_id"] == "bounded-candidate"
    assert result["cost_metadata"] == {
        "model_calls": 1,
        "model": "test-model",
        "input_tokens": 20,
        "output_tokens": 10,
        "total_tokens": 30,
        "wall_time_seconds": 0.25,
        "endpoint_profile": "openai_compatible",
        "json_repair_count": 0,
    }


def test_statement_splitter_ignores_literals_comments_and_multiline_calls() -> None:
    source = (
        "static void shifted(void) {\n"
        "  char *item = calloc(1, 8); /* ; } */\n"
        "  memcpy(\n"
        "    &item->field, \"};\", 2);\n"
        "  item->flag = 1;\n"
        "}\n"
    )

    statements = split_c_statements(source)

    assert [item.start_line for item in statements] == [1, 2, 3, 5]
    assert "memcpy(" in statements[2].normalized
    assert statements[2].end_line == 4


def test_null_verifier_accepts_exact_first_dereference_without_names_or_lines(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _source, pack_path, pack = _null_campaign(
        tmp_path,
        monkeypatch,
        body_lines=[
            "    struct record *fresh;",
            "    fresh = calloc(1, sizeof(*fresh));",
            "    fresh->flag = 1;",
        ],
        candidate_body_line=3,
    )
    proposal = _write_null_proposal(root, pack, decision="bug")

    result = verify_investigation_proposal(root, pack_path, proposal)

    assert result.verified is True
    assert result.decision == "bug"
    assert result.basis == "exact_source_feasible_violation"
    assert result.proof["pointer"] == "fresh"
    assert result.proof["allocator"] == "calloc"
    assert result.proof["earlier_dereferences"] == []
    assert result.root_cause["root_cause_id"]
    assert result.nearby_defects == ()


def test_null_verifier_rejects_bug_prose_when_an_earlier_fault_is_mandatory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _source, pack_path, pack = _null_campaign(
        tmp_path,
        monkeypatch,
        body_lines=[
            "    struct record *fresh;",
            "    struct record other = {0};",
            "    fresh = calloc(1, sizeof(*fresh));",
            "    memcpy(&fresh->copy, &other.copy, sizeof(other.copy));",
            "    fresh->flag = 1;",
        ],
        candidate_body_line=5,
    )
    wrong = _write_null_proposal(root, pack, decision="bug")

    rejected = verify_investigation_proposal(root, pack_path, wrong)

    assert rejected.verified is False
    assert "disagrees" in rejected.rejection_reason
    assert rejected.proof["derived_decision"] == "not_bug"

    correct = _write_null_proposal(root, pack, decision="not_bug")
    result = verify_investigation_proposal(root, pack_path, correct)
    assert result.verified is True
    assert result.decision == "not_bug"
    assert result.basis == "cfg_smt_path_infeasible"
    assert result.proof["null_path_reaches_candidate"] is False
    assert "memcpy" in result.proof["earliest_fault"]["normalized"]
    assert len(result.nearby_defects) == 1
    assert result.nearby_defects[0]["kind"] == "unchecked_allocation"
    assert result.nearby_defects[0]["candidate_replacement_forbidden"] is True


def test_null_verifier_proves_dominating_terminating_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _source, pack_path, pack = _null_campaign(
        tmp_path,
        monkeypatch,
        body_lines=[
            "    struct record *fresh;",
            "    fresh = calloc(1, sizeof(*fresh));",
            "    if (!fresh)",
            "        return;",
            "    fresh->flag = 1;",
        ],
        candidate_body_line=5,
    )
    proposal = _write_null_proposal(root, pack, decision="not_bug")

    result = verify_investigation_proposal(root, pack_path, proposal)

    assert result.verified is True
    assert result.decision == "not_bug"
    assert result.basis == "source_proves_safety"
    assert result.proof["claims"]["dominating_nonnull_guard"] is True
    assert result.nearby_defects == ()


def test_semantic_verifier_rejects_changed_exact_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _source, pack_path, pack = _null_campaign(
        tmp_path,
        monkeypatch,
        body_lines=[
            "    struct record *fresh;",
            "    fresh = calloc(1, sizeof(*fresh));",
            "    fresh->flag = 1;",
        ],
        candidate_body_line=3,
    )
    proposal = _write_null_proposal(root, pack, decision="bug")
    payload = json.loads(proposal.read_text())
    payload["exact_operation"]["address"] = "0xDEADBEEF"
    proposal.write_text(json.dumps(payload))

    with pytest.raises(VerificationError, match="address changed"):
        verify_investigation_proposal(root, pack_path, proposal)


def test_spatial_verifier_uses_capacity_width_and_groups_shifted_stores(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, pack_paths, packs = _spatial_campaign(tmp_path, monkeypatch)
    results = []
    for pack_path, pack in zip(pack_paths, packs):
        proposal = _write_spatial_proposal(root, pack, "bug")
        results.append(verify_investigation_proposal(root, pack_path, proposal))

    assert [result.decision for result in results] == ["bug", "bug"]
    assert all(result.verified for result in results)
    assert results[0].proof["capacity_bytes"] == 16
    assert results[0].proof["write_interval"] == {
        "start_offset": 15,
        "end_offset_exclusive": 17,
        "capacity_bytes": 16,
        "overflow_bytes": 1,
    }
    assert results[1].proof["write_interval"]["start_offset"] == 16
    assert results[0].root_cause["root_cause_id"] == results[1].root_cause["root_cause_id"]


def test_spatial_verifier_proves_shifted_capacity_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, pack_paths, packs = _spatial_campaign(tmp_path, monkeypatch, guarded=True)
    proposal = _write_spatial_proposal(root, packs[0], "not_bug")

    result = verify_investigation_proposal(root, pack_paths[0], proposal)

    assert result.verified is True
    assert result.decision == "not_bug"
    assert result.basis == "source_proves_safety"
    assert result.proof["claims"]["dominating_bounds_guard"] is True


def test_autonomous_verifier_has_no_frozen_candidate_or_source_line_rules() -> None:
    verifier = Path("src/binary_agent/adjudication_verifier.py").read_text()
    investigation = Path("src/binary_agent/adjudication_investigation.py").read_text()
    source = verifier + investigation

    assert not re.search(r"\b[0-9a-f]{16}\b", source)
    assert "required_source_line" not in source
    assert "suppression" not in source.lower()


def test_investigation_stage_groups_deterministic_holdouts_without_model_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _pack_paths, packs = _spatial_campaign(tmp_path, monkeypatch)

    result = run_investigation_stage(
        root,
        direct_provider=None,
        agent_provider=None,
        output_dir=root / "autonomous-stage",
        candidate_ids=[pack["candidate_id"] for pack in packs],
    )

    assert len(result.verified) == 2
    assert result.residual_candidate_ids == ()
    assert result.direct_attempt_count == 0
    assert result.agent_attempt_count == 0
    assert result.root_cause_group_count == 1
    summary = json.loads(result.summary_path.read_text())
    groups_path = root / summary["root_cause_groups"]["path"]
    groups = json.loads(groups_path.read_text())
    assert groups["groups"][0]["candidate_ids"] == [
        "shifted-store-a",
        "shifted-store-b",
    ]


def test_investigation_stage_escalates_unverified_direct_proposal_to_agent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _source, candidate_id = _source_bound_campaign(
        tmp_path,
        monkeypatch,
        vulnerability_type="uninitialized_memory_use",
    )

    class EscalatingProvider:
        def __init__(self) -> None:
            self.tiers: list[str] = []

        def investigate(self, pack: dict, *, tier: str) -> dict:
            self.tiers.append(tier)
            proposal = _proposal(pack["candidate_id"])
            proposal["claim_kind"] = "unresolved"
            return proposal

    provider = EscalatingProvider()
    result = run_investigation_stage(
        root,
        direct_provider=provider,
        agent_provider=provider,
        output_dir=root / "autonomous-stage",
        direct_call_cap=1,
        agent_call_cap=1,
    )

    assert provider.tiers == ["direct", "agent"]
    assert result.direct_attempt_count == 1
    assert result.agent_attempt_count == 1
    assert result.residual_candidate_ids == (candidate_id,)
    assert result.verified == {}
