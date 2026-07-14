import json
from pathlib import Path

import pytest

from binary_agent.cli.toolchain import _load_process_input_override
from binary_agent.corpus_runner import load_corpus_manifest, run_corpus
from binary_agent.discovery import discover_candidates, load_discovery_context
from tests.test_end_to_end_pipeline import _write_export


FIXTURES = Path(__file__).parent / "fixtures"


def test_registered_semantic_oracles_emit_structural_observations(tmp_path: Path) -> None:
    manifest = FIXTURES / "schema2_registered_semantic" / "manifest.json"
    summary = run_corpus(load_corpus_manifest(manifest), tmp_path / "semantic", mode="lightweight")

    assert summary.accepted is True
    assert summary.totals["reports"] == 7
    assert summary.totals["fixed_reports"] == 0
    by_id = {lane.lane_id: lane for lane in summary.lanes}
    expected_detail = {
        "argument-injection-vulnerable": "child_argv",
        "code-injection-vulnerable": "interpreter_action",
        "ssrf-vulnerable": "listener",
        "sql-injection-vulnerable": "attacker_table",
        "http-header-injection-vulnerable": "headers",
        "log-injection-vulnerable": "record_count",
        "open-redirect-vulnerable": "locations",
    }
    for lane_id, detail_key in expected_detail.items():
        payload = json.loads(
            (Path(by_id[lane_id].run_dir) / "proof" / "proof_results.json").read_text()
        )
        proof = payload["proof_results"][0]
        assert proof["status"] == "proven"
        assert proof["effect_observation"]["status"] == "observed"
        assert proof["effect_observation"]["sink_address"]
        assert proof["effect_observation"]["concrete_input_fingerprint"]
        assert detail_key in proof["effect_observation"]["details"]


def test_registered_static_proof_is_consumer_gated_and_redacted(tmp_path: Path) -> None:
    manifest = FIXTURES / "schema2_registered_static" / "manifest.json"
    summary = run_corpus(load_corpus_manifest(manifest), tmp_path / "static", mode="lightweight")

    assert summary.accepted is True
    assert summary.totals["reports"] == 6
    assert summary.totals["fixed_reports"] == 0
    serialized = ""
    for lane in summary.lanes:
        if lane.role != "vulnerable":
            continue
        root = Path(lane.run_dir)
        serialized += (root / "discovery" / "candidates.json").read_text()
        serialized += (root / "proof" / "proof_results.json").read_text()
        serialized += (root / "report" / "vulnerabilities.json").read_text()
    for secret in (
        "Firmware#42",
        "MDECAQMEBQYHCAkKCwwNDg8Q",
        "AbCDef_1234567890-ghIJ",
    ):
        assert secret not in serialized
    assert "literal_fingerprint" in serialized
    assert "consumer_address" in serialized


def test_process_configuration_cannot_predeclare_an_observed_effect(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "input_model": "argv",
                "argv_values": ["value"],
                "proof_oracle": {"status": "observed"},
            }
        )
    )
    with pytest.raises(ValueError, match="cannot declare proof_oracle.status"):
        _load_process_input_override(invalid)

    valid = tmp_path / "valid.json"
    valid.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "input_model": "argv",
                "argv_values": ["{listener_port}"],
                "cwd": "{candidate_dir}",
                "outbound_listener": {"host": "127.0.0.1", "port": 0},
                "proof_oracle": {"created_table": "attacker_created"},
            }
        )
    )
    loaded = _load_process_input_override(valid)
    assert loaded["cwd"] == "{candidate_dir}"
    assert loaded["outbound_listener"]["port"] == 0


def test_program_index_preserves_alias_roles_literal_consumers_and_scope_paths(tmp_path: Path) -> None:
    export = _write_export(
        tmp_path,
        {
            "main.c": (
                "void main(void *ctx, int flag){\n"
                "SSL_CTX_set_verify(ctx, 0, 0);\n"
                "authenticate(\"admin\", \"Firmware#42\");\n"
                "char *ptr = malloc(16);\n"
                "if (flag) return;\n"
                "free(ptr);\n"
                "}"
            )
        },
    )
    index = load_discovery_context(export).index
    verify = next(item for item in index.operations if item.name == "ssl_ctx_set_verify")
    assert verify.observed_name == "SSL_CTX_set_verify"
    assert verify.role("verify_mode") == "0"
    assert {item.argument_role for item in index.literal_consumers if item.consumer_name == "authenticate"} == {
        "username",
        "password",
    }
    assert index.scope_exits
    assert any(item.live_at_exit for item in index.resource_paths)


@pytest.mark.parametrize(
    "source",
    [
        "char *main(void){ char *ptr = malloc(16); return ptr; }",
        "char *global_ptr; void main(void){ char *ptr = malloc(16); global_ptr = ptr; }",
        "void main(char **param_1){ char *ptr = malloc(16); *param_1 = ptr; }",
        "void main(void){ char *ptr = malloc(16); take_ownership(ptr); }",
    ],
)
def test_memory_leak_suppresses_ownership_escape_and_unresolved_transfer(
    tmp_path: Path,
    source: str,
) -> None:
    export = _write_export(tmp_path, {"main.c": source})
    states = discover_candidates(
        load_discovery_context(export),
        backend_names=["memory_lifetime"],
        vulnerability_types=["memory_leak"],
    )
    assert states == []
