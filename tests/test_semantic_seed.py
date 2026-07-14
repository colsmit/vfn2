import argparse
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

import pytest

from binary_agent.cli.toolchain import _enforce_live_llm_if_required
from binary_agent.cli import toolchain as toolchain_cli
from binary_agent.analysis.hypothesis_generation import run_hypothesis_stage
from binary_agent.data.manifest import FunctionRecord, Manifest
from binary_agent.discovery.semantic_seed import (
    ExternalCommandSemanticSeedProvider,
    build_semantic_feature_index,
    run_semantic_seed_stage,
    semantic_seed_candidates_from_artifacts,
)
from binary_agent.pipeline import CandidateState, CandidateStatus
from binary_agent.promotion import promote_proof_ready
from binary_agent.replay import runners as replay_runners
from binary_agent.replay import ReplayRequest, build_replay_plan, build_replay_requests, run_replay_plan, run_replay_request
from scripts import llm_hypothesis_provider, llm_replay_repair_provider, llm_semantic_seed_provider


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _record(name: str, address: str, relative_path: str, text: str, *, strings: list[str] | None = None) -> FunctionRecord:
    return FunctionRecord(
        address=address,
        relative_address=int(address, 16),
        name=name,
        relative_path=relative_path,
        source_exists=True,
        ordinal=0,
        size_addresses=16,
        body_size_bytes=len(text),
        is_thunk=False,
        stack_purge=None,
        call_fixup=None,
        decompile_completed=True,
        byte_length=len(text.encode()),
        line_count=len(text.splitlines()),
        return_type="void",
        prototype=f"void {name}(void)",
        parameters=[],
        emit_c=True,
        string_refs=[{"value": item} for item in (strings or [])],
        pcode_calls=[],
        pcode_stores=[],
        ambiguous_callsites=[],
    )


def _write_export(tmp_path: Path, sources: Mapping[str, str], *, string_refs: Mapping[str, list[str]] | None = None) -> Path:
    export_dir = tmp_path / "decompiled"
    export_dir.mkdir()
    records = []
    for index, (relative_path, text) in enumerate(sources.items()):
        (export_dir / relative_path).write_text(text)
        name = relative_path.removesuffix(".c")
        records.append(
            _record(
                name,
                f"0x{0x1000 + index * 0x100:x}",
                relative_path,
                text,
                strings=(string_refs or {}).get(relative_path, []),
            )
        )
    manifest = Manifest(
        binary="demo.bin",
        generated_at="2026-05-16T00:00:00Z",
        export_dir=str(export_dir),
        image_base=0,
        ghidra_manifest=str(export_dir / "manifest.jsonl"),
        callgraph_path=None,
        functions=records,
    )
    (export_dir / "manifest_normalized.json").write_text(json.dumps(manifest.to_dict()))
    return export_dir


def _write_intake(tmp_path: Path) -> Path:
    intake_dir = tmp_path / "intake"
    intake_dir.mkdir()
    (intake_dir / "routes.json").write_text(
        json.dumps({"routes": [{"route": "/cgi-bin/diag", "method": "POST"}]})
    )
    (intake_dir / "services.json").write_text(json.dumps({"services": []}))
    (intake_dir / "configs.json").write_text(
        json.dumps({"configs": [{"relative_path": "etc/app.conf", "env_keys": ["UPLOAD_DIR"]}]})
    )
    (intake_dir / "target.json").write_text(json.dumps({"path": str(tmp_path)}))
    (intake_dir / "binaries.json").write_text(json.dumps({"binaries": []}))
    (intake_dir / "analysis_manifest.json").write_text(json.dumps({}))
    return intake_dir


class SemanticProvider:
    def generate(self, pack: Mapping[str, Any], *, phase: str, vuln_class: str) -> Mapping[str, Any]:
        if phase == "cluster_triage":
            return {
                "accepted_clusters": [{"cluster_id": pack["clusters"][0]["cluster_id"]}],
                "cost_metadata": {"model_calls": 1, "input_tokens": 10, "output_tokens": 5},
            }
        cluster = pack["cluster"]
        anchor = cluster["anchors"][0]
        return {
            "seeds": [
                {
                    "vulnerability_type": vuln_class,
                    "cluster_id": cluster["cluster_id"],
                    "string_signal_id": cluster["string_signal"]["signal_id"],
                    "string_anchor": cluster["string_signal"]["anchor"],
                    "anchors": [anchor],
                    "source": {"kind": "route", "expression": "/cgi-bin/diag"},
                    "sink": {"name": "system", "kind": "command_execution"},
                    "replay_hints": {
                        "mode": "native",
                        "setup": {},
                        "input": {},
                        "expected_result": {
                            "sink_output_contains": "SEMANTIC_MARKER",
                            "proof_oracle": {"kind": "command_effect", "marker": "SEMANTIC_MARKER"},
                        },
                    },
                }
            ],
            "cost_metadata": {"model_calls": 1, "input_tokens": 20, "output_tokens": 10},
        }


def test_feature_index_clusters_and_seed_conversion(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {"cmd.c": "void cmd(char **argv){ system(argv[1]); }\n"},
        string_refs={"cmd.c": ["/bin/sh", "diagnostic"]},
    )
    intake_dir = _write_intake(tmp_path)

    feature_index = build_semantic_feature_index(export_dir, intake_dir=intake_dir)
    result = run_semantic_seed_stage(
        export_dir,
        tmp_path / "semantic",
        intake_dir=intake_dir,
        provider=SemanticProvider(),
        classes=["command_injection"],
        max_clusters_per_class=1,
    )
    states = semantic_seed_candidates_from_artifacts(tmp_path / "semantic", binary_path=tmp_path / "demo")

    assert feature_index["functions"][0]["function_name"] == "cmd"
    assert "system" in feature_index["functions"][0]["calls"]
    assert feature_index["routes"][0]["route"] == "/cgi-bin/diag"
    assert result.summary["accepted_count"] == 1
    assert result.summary["model_calls"] == 1
    assert result.summary["funnel_metrics"]["string_signals"]["command_injection"] == 1
    accepted = json.loads(next((tmp_path / "semantic" / "accepted").glob("*.json")).read_text())
    assert accepted["string_signal_id"]
    assert accepted["proof_oracle_kind"] == "command_effect"
    assert accepted["deterministic_replay_intent"]["proof_oracle_kind"] == "command_effect"
    assert states[0].metadata["provenance"] == "llm_semantic_seed"
    assert states[0].metadata["semantic_string_anchor"] in {"/bin/sh", "diagnostic"}
    assert states[0].validation_artifacts[0].endswith(".json")


def test_source_sink_fallback_clusters_without_literal_string(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {"cmd.c": "void cmd(char **argv){ system(argv[1]); }\n"},
    )

    class SourceSinkProvider:
        def generate(self, pack: Mapping[str, Any], *, phase: str, vuln_class: str) -> Mapping[str, Any]:
            cluster = pack["cluster"]
            anchor = cluster["anchors"][0]
            signal = cluster["string_signal"]
            features = cluster["features"]
            return {
                "seeds": [
                    {
                        "vulnerability_type": vuln_class,
                        "cluster_id": cluster["cluster_id"],
                        "string_signal_id": signal["signal_id"],
                        "string_anchor": signal["anchor"],
                        "anchors": [anchor],
                        "source": {"kind": "argv", "expression": features["source_expression"]},
                        "sink": {"name": features["sink_name"], "kind": "command_execution"},
                        "proof_oracle": {"kind": "command_effect", "marker": "SEMANTIC_MARKER"},
                        "replay_hints": {
                            "mode": "native",
                            "input": {"argv": ["demo", "SEMANTIC_MARKER"]},
                            "expected_result": {
                                "proof_oracle": {"kind": "command_effect", "marker": "SEMANTIC_MARKER"}
                            },
                        },
                    }
                ],
                "cost_metadata": {"model_calls": 1},
            }

    result = run_semantic_seed_stage(
        export_dir,
        tmp_path / "semantic_source_sink",
        provider=SourceSinkProvider(),
        classes=["command_injection"],
        max_clusters_per_class=1,
    )
    states = semantic_seed_candidates_from_artifacts(tmp_path / "semantic_source_sink", binary_path=tmp_path / "demo")

    assert result.summary["cluster_counts"]["command_injection"] == 1
    assert result.summary["accepted_count"] == 1
    assert states[0].metadata["semantic_string_anchor"].startswith("command source argv")
    assert states[0].sink["name"] == "system"


def test_source_sink_fallback_rejects_generic_wrapper_anchor(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {"execv.c": "void execv(char **argv){ execv(argv[0], argv); }\n"},
    )

    class WrapperProvider:
        def generate(self, pack: Mapping[str, Any], *, phase: str, vuln_class: str) -> Mapping[str, Any]:
            cluster = pack["cluster"]
            signal = cluster["string_signal"]
            features = cluster["features"]
            return {
                "seeds": [
                    {
                        "vulnerability_type": vuln_class,
                        "cluster_id": cluster["cluster_id"],
                        "string_signal_id": signal["signal_id"],
                        "string_anchor": signal["anchor"],
                        "anchors": [cluster["anchors"][0]],
                        "source": {"kind": "argv", "expression": features["source_expression"]},
                        "sink": {"name": features["sink_name"], "kind": "command_execution"},
                        "proof_oracle": {"kind": "command_effect", "marker": "SEMANTIC_MARKER"},
                        "replay_hints": {
                            "mode": "native",
                            "expected_result": {
                                "proof_oracle": {"kind": "command_effect", "marker": "SEMANTIC_MARKER"}
                            },
                        },
                    }
                ],
                "cost_metadata": {"model_calls": 1},
            }

    result = run_semantic_seed_stage(
        export_dir,
        tmp_path / "semantic_wrapper",
        provider=WrapperProvider(),
        classes=["command_injection"],
        max_clusters_per_class=1,
    )
    rejected = json.loads(result.rejected_index_path.read_text())["rejected"][0]

    assert result.summary["accepted_count"] == 0
    assert "generic_sink_wrapper_anchor" in rejected["failure_reason"]


def test_zoom_budget_round_robins_across_classes(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "cmd.c": "void cmd(char **argv){ system(argv[1]); }\n",
            "download.c": "void download(char **argv){ fopen(argv[1], \"r\"); }\n",
            "upload.c": "void upload(char **argv){ FILE *f=fopen(argv[1], \"w\"); fwrite(argv[2],1,4,f); }\n",
        },
    )

    class CountingProvider:
        def __init__(self) -> None:
            self.classes: list[str] = []

        def generate(self, pack: Mapping[str, Any], *, phase: str, vuln_class: str) -> Mapping[str, Any]:
            self.classes.append(vuln_class)
            return {}

    provider = CountingProvider()
    run_semantic_seed_stage(
        export_dir,
        tmp_path / "semantic_round_robin",
        provider=provider,
        classes=["command_injection", "path_traversal", "unsafe_file_write"],
        max_clusters_per_class=2,
        max_zoom_seeds=3,
    )

    assert provider.classes == ["command_injection", "path_traversal", "unsafe_file_write"]


def test_seed_validation_rejects_hallucinated_anchor_and_proof_claim(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {"cmd.c": "void cmd(char **argv){ system(argv[1]); }\n"},
        string_refs={"cmd.c": ["/bin/sh"]},
    )

    class BadProvider:
        def generate(self, pack: Mapping[str, Any], *, phase: str, vuln_class: str) -> Mapping[str, Any]:
            if phase == "cluster_triage":
                return {"accepted_clusters": [{"cluster_id": pack["clusters"][0]["cluster_id"]}], "cost_metadata": {"model_calls": 1}}
            return {
                "seeds": [
                    {
                        "vulnerability_type": vuln_class,
                        "cluster_id": pack["cluster"]["cluster_id"],
                        "anchors": [{"kind": "function", "function_name": "not_real", "address": "0x9999"}],
                        "sink": {"name": "system"},
                        "status": "confirmed",
                    }
                ],
                "cost_metadata": {"model_calls": 1},
            }

    result = run_semantic_seed_stage(export_dir, tmp_path / "semantic", provider=BadProvider(), classes=["command_injection"])
    rejected = json.loads(result.rejected_index_path.read_text())["rejected"][0]

    assert result.summary["accepted_count"] == 0
    assert "unknown_address" in rejected["failure_reason"]
    assert "seed_claims_proof_or_reportability" in rejected["failure_reason"]


def test_sink_only_context_does_not_call_semantic_provider(tmp_path: Path) -> None:
    export_dir = _write_export(tmp_path, {"cmd.c": "void cmd(void){ system(\"date\"); }\n"})

    class CountingProvider:
        calls = 0

        def generate(self, pack: Mapping[str, Any], *, phase: str, vuln_class: str) -> Mapping[str, Any]:
            self.calls += 1
            return {}

    provider = CountingProvider()
    result = run_semantic_seed_stage(
        export_dir,
        tmp_path / "semantic_sink_only",
        provider=provider,
        classes=["command_injection"],
    )

    assert provider.calls == 0
    assert result.summary["accepted_count"] == 0
    assert result.summary["funnel_metrics"]["string_signals"].get("command_injection", 0) == 0


def test_path_traversal_and_unsafe_write_require_class_oracles(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "download.c": "void download(char **argv){ fopen(argv[1], \"r\"); }\n",
            "upload.c": "void upload(char **argv){ FILE *f=fopen(argv[1], \"w\"); fwrite(argv[2],1,4,f); }\n",
        },
        string_refs={
            "download.c": ["download"],
            "upload.c": ["upload"],
        },
    )

    class ClassProvider:
        def generate(self, pack: Mapping[str, Any], *, phase: str, vuln_class: str) -> Mapping[str, Any]:
            cluster = pack["cluster"]
            signal = cluster["string_signal"]
            oracle = {
                "path_traversal": "filesystem_read_escape",
                "unsafe_file_write": "filesystem_write_escape",
            }[vuln_class]
            sink = "fopen" if vuln_class == "path_traversal" else "fwrite"
            return {
                "seeds": [
                    {
                        "vulnerability_type": vuln_class,
                        "cluster_id": cluster["cluster_id"],
                        "string_signal_id": signal["signal_id"],
                        "string_anchor": signal["anchor"],
                        "anchors": [cluster["anchors"][0]],
                        "source": {"kind": "argv", "expression": "argv[1]"},
                        "sink": {"name": sink},
                        "proof_oracle": {"kind": oracle, "marker": "SEMANTIC_MARKER"},
                        "replay_hints": {
                            "mode": "native",
                            "expected_result": {"proof_oracle": {"kind": oracle, "marker": "SEMANTIC_MARKER"}},
                        },
                    }
                ],
                "cost_metadata": {"model_calls": 1},
            }

    result = run_semantic_seed_stage(
        export_dir,
        tmp_path / "semantic_path_write",
        provider=ClassProvider(),
        classes=["path_traversal", "unsafe_file_write"],
        max_clusters_per_class=1,
    )

    accepted = json.loads(result.accepted_index_path.read_text())["accepted"]
    assert result.summary["accepted_count"] == 2
    assert {row["vulnerability_type"] for row in accepted} == {"path_traversal", "unsafe_file_write"}
    assert result.summary["funnel_metrics"]["context_packs"] == {"path_traversal": 1, "unsafe_file_write": 1}


def test_semantic_seed_rejects_non_path_and_non_write_file_effect_sinks(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "download.c": "void download(char **argv){ int fd=open(argv[1],0); read(fd,argv[2],4); }\n",
            "upload.c": "void upload(char **argv){ unlink(argv[1]); write(1,argv[2],4); }\n",
        },
        string_refs={
            "download.c": ["download path"],
            "upload.c": ["upload write"],
        },
    )

    class BadSinkProvider:
        def generate(self, pack: Mapping[str, Any], *, phase: str, vuln_class: str) -> Mapping[str, Any]:
            cluster = pack["cluster"]
            signal = cluster["string_signal"]
            oracle = {
                "path_traversal": "filesystem_read_escape",
                "unsafe_file_write": "filesystem_write_escape",
            }[vuln_class]
            sink = "read" if vuln_class == "path_traversal" else "unlink"
            return {
                "seeds": [
                    {
                        "vulnerability_type": vuln_class,
                        "cluster_id": cluster["cluster_id"],
                        "string_signal_id": signal["signal_id"],
                        "string_anchor": signal["anchor"],
                        "anchors": [cluster["anchors"][0]],
                        "source": {"kind": "argv", "expression": "argv[1]"},
                        "sink": {"name": sink},
                        "proof_oracle": {"kind": oracle},
                        "replay_hints": {
                            "mode": "function_harness",
                            "expected_result": {"proof_oracle": {"kind": oracle}},
                        },
                    }
                ],
                "cost_metadata": {"model_calls": 1},
            }

    result = run_semantic_seed_stage(
        export_dir,
        tmp_path / "semantic_bad_file_sinks",
        provider=BadSinkProvider(),
        classes=["path_traversal", "unsafe_file_write"],
        max_clusters_per_class=1,
    )

    rejected = json.loads(result.rejected_index_path.read_text())["rejected"]
    assert result.summary["accepted_count"] == 0
    assert result.summary["rejected_count"] == 2
    assert all("sink_wrong_class" in row["failure_reason"] for row in rejected)


def test_semantic_acceptance_rejects_missing_source_sink_or_oracle(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {"cmd.c": "void cmd(char **argv){ system(argv[1]); }\n"},
        string_refs={"cmd.c": ["ping"]},
    )

    class IncompleteProvider:
        def generate(self, pack: Mapping[str, Any], *, phase: str, vuln_class: str) -> Mapping[str, Any]:
            cluster = pack["cluster"]
            signal = cluster["string_signal"]
            return {
                "seeds": [
                    {
                        "vulnerability_type": vuln_class,
                        "cluster_id": cluster["cluster_id"],
                        "string_signal_id": signal["signal_id"],
                        "string_anchor": signal["anchor"],
                        "anchors": [cluster["anchors"][0]],
                        "sink": {"name": "system"},
                    }
                ],
                "cost_metadata": {"model_calls": 1},
            }

    result = run_semantic_seed_stage(
        export_dir,
        tmp_path / "semantic_incomplete",
        provider=IncompleteProvider(),
        classes=["command_injection"],
        max_clusters_per_class=1,
    )
    rejected = json.loads(result.rejected_index_path.read_text())["rejected"][0]["failure_reason"]

    assert result.summary["accepted_count"] == 0
    assert "missing_concrete_source" in rejected
    assert "missing_class_oracle" in rejected
    assert "missing_deterministic_replay_intent" in rejected


def test_provider_command_success_failure_and_timeout(tmp_path: Path) -> None:
    ok = tmp_path / "ok_provider.py"
    ok.write_text("import json,sys; json.load(sys.stdin); print(json.dumps({'accepted_clusters': [], 'cost_metadata': {'model_calls': 1}}))\n")
    fail = tmp_path / "fail_provider.py"
    fail.write_text("import sys; sys.stderr.write('bad'); sys.exit(2)\n")
    slow = tmp_path / "slow_provider.py"
    slow.write_text("import time; time.sleep(2)\n")

    provider = ExternalCommandSemanticSeedProvider([os.environ.get("PYTHON", "python3"), str(ok)], timeout_seconds=1)
    assert provider.generate({"clusters": []}, phase="cluster_triage", vuln_class="command_injection")["cost_metadata"]["model_calls"] == 1

    with pytest.raises(RuntimeError, match="exited with status"):
        ExternalCommandSemanticSeedProvider([os.environ.get("PYTHON", "python3"), str(fail)], timeout_seconds=1).generate({}, phase="x", vuln_class="y")
    with pytest.raises(RuntimeError, match="timed out"):
        ExternalCommandSemanticSeedProvider([os.environ.get("PYTHON", "python3"), str(slow)], timeout_seconds=0.1).generate({}, phase="x", vuln_class="y")


def test_live_provider_scripts_default_to_oss_120b_and_accept_openai_compatible_options(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "BINARY_AGENT_SEMANTIC_SEED_MODEL",
        "BINARY_AGENT_HYPOTHESIS_MODEL",
        "BINARY_AGENT_REPLAY_REPAIR_MODEL",
        "OPENROUTER_MODEL",
        "OPENROUTER_CHAT_COMPLETIONS_URL",
        "OPENAI_BASE_URL",
        "OPENAI_COMPAT_BASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)

    semantic_args = llm_semantic_seed_provider.parse_args([])
    hypothesis_args = llm_hypothesis_provider.parse_args(["--base-url", "https://llm.example/v1", "--api-key-env", "OSS_KEY"])
    repair_args = llm_replay_repair_provider.parse_args([])

    assert semantic_args.model == "gpt-oss-120b"
    assert repair_args.model == "gpt-oss-120b"
    assert hypothesis_args.model == "gpt-oss-120b"
    assert hypothesis_args.url == "https://llm.example/v1/chat/completions"
    assert hypothesis_args.api_key_env == "OSS_KEY"


def test_toolchain_auto_llm_provider_command_resolves_builtin_script() -> None:
    command = toolchain_cli._llm_provider_command("auto", "llm_hypothesis_provider.py")

    assert "llm_hypothesis_provider.py" in command
    assert "--yes-live" in command
    assert command.startswith(sys.executable)


def test_live_hypothesis_provider_normalizes_http_route_query_into_inputs() -> None:
    normalized = llm_hypothesis_provider._normalize(
        {
            "hypothesis_kind": "replay",
            "proposed_setup": {"mode": "native", "routes": [{"method": "GET", "path": "/diag?cmd=id"}]},
            "proposed_inputs": {"argv": [], "body": "", "form": {}, "stdin": ""},
            "expected_sink": {"function_name": "system", "sink": "grounded"},
            "proof_oracle": {"kind": "command_effect", "marker": "uid="},
        },
        {
            "candidate_id": "http-cand",
            "location": {"function_name": "handle_http", "address": "0x1200"},
            "sink": {"name": "system", "operation_address": "0x1210"},
            "facts_available_to_llm": {
                "process_input": {"input_model": "http_daemon"},
            },
        },
    )

    assert normalized["proposed_inputs"]["input_model"] == "http_daemon"
    assert normalized["proposed_inputs"]["path"] == "/diag"
    assert normalized["proposed_inputs"]["query"] == {"cmd": "id"}
    assert "argv" not in normalized["proposed_inputs"]
    assert "body" not in normalized["proposed_inputs"]
    assert "form" not in normalized["proposed_inputs"]
    assert "stdin" not in normalized["proposed_inputs"]
    assert normalized["proposed_setup"]["routes"][0]["path"] == "/diag"
    assert normalized["expected_sink"]["function_name"] == "handle_http"
    assert normalized["expected_sink"]["sink"] == "system"
    assert normalized["expected_sink"]["operation_address"] == "0x1210"
    assert normalized["expected_sink"]["proof_oracle"]["kind"] == "command_effect"


def test_live_hypothesis_provider_normalizes_socket_service_inputs() -> None:
    normalized = llm_hypothesis_provider._normalize(
        {
            "hypothesis_kind": "replay",
            "proposed_setup": {
                "mode": "native",
                "services": [{"protocol": "tcp", "host": "127.0.0.1", "port": "31337"}],
            },
            "proposed_inputs": {"payload": "RUN id\n", "body": "", "argv": []},
            "expected_sink": {"function_name": "system", "sink": "grounded"},
            "proof_oracle": {"kind": "command_effect", "marker": "uid="},
        },
        {
            "candidate_id": "socket-cand",
            "location": {"function_name": "handle_socket", "address": "0x2200"},
            "sink": {"name": "system", "operation_address": "0x2210"},
            "facts_available_to_llm": {
                "process_input": {"input_model": "socket_service"},
            },
        },
    )

    assert normalized["proposed_inputs"]["input_model"] == "socket_service"
    assert normalized["proposed_inputs"]["payload"] == "RUN id\n"
    assert "body" not in normalized["proposed_inputs"]
    assert "argv" not in normalized["proposed_inputs"]
    assert normalized["expected_sink"]["function_name"] == "handle_socket"
    assert normalized["expected_sink"]["sink"] == "system"
    assert normalized["expected_sink"]["proof_oracle"]["kind"] == "command_effect"


def test_replay_repair_provider_normalizes_grounded_expected_sink() -> None:
    normalized = llm_replay_repair_provider._normalize(
        {
            "hypothesis_kind": "replay",
            "proposed_setup": {"mode": "native"},
            "proposed_inputs": {"payload": "RUN id\n", "stdin": "", "argv": []},
            "expected_sink": {"function_name": "system", "sink": "grounded"},
        },
        {
            "candidate_id": "repair-cand",
            "request": {
                "expected_result": {
                    "function_name": "handle_socket",
                    "sink": "system",
                    "sink_address": "0x2210",
                    "proof_oracle": {"kind": "command_effect", "marker": "uid="},
                }
            },
        },
    )

    assert normalized["expected_sink"]["function_name"] == "handle_socket"
    assert normalized["expected_sink"]["sink"] == "system"
    assert normalized["expected_sink"]["operation_address"] == "0x2210"
    assert normalized["expected_sink"]["proof_oracle"]["kind"] == "command_effect"
    assert normalized["proposed_inputs"] == {"payload": "RUN id\n"}


def test_require_live_llm_rejects_disabled_fixture_and_zero_call_summaries(tmp_path: Path) -> None:
    args = argparse.Namespace(require_live_llm=True)
    disabled = tmp_path / "disabled.json"
    disabled.write_text(json.dumps({"enabled": False, "provider": "disabled", "model_calls": 0}))
    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps({"enabled": True, "provider": "FixtureHypothesisProvider", "model_calls": 1}))
    zero = tmp_path / "zero.json"
    zero.write_text(json.dumps({"enabled": True, "provider": "ExternalCommandHypothesisProvider", "model_calls": 0}))
    live = tmp_path / "live.json"
    live.write_text(json.dumps({"enabled": True, "provider": "ExternalCommandHypothesisProvider", "model_calls": 1}))

    with pytest.raises(RuntimeError, match="enabled"):
        _enforce_live_llm_if_required(args, disabled, "semantic_seed")
    with pytest.raises(RuntimeError, match="non-live"):
        _enforce_live_llm_if_required(args, fixture, "hypothesis")
    with pytest.raises(RuntimeError, match="model_calls"):
        _enforce_live_llm_if_required(args, zero, "hypothesis")
    _enforce_live_llm_if_required(args, live, "hypothesis")


def test_semantic_seed_does_not_create_direct_replay_request(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {"cmd.c": "void cmd(char **argv){ system(argv[1]); }\n"},
        string_refs={"cmd.c": ["/bin/sh"]},
    )
    run_semantic_seed_stage(export_dir, tmp_path / "semantic", provider=SemanticProvider(), classes=["command_injection"])
    states = semantic_seed_candidates_from_artifacts(tmp_path / "semantic", binary_path=tmp_path / "marker.sh")
    proof_ready, _, _ = promote_proof_ready(states)

    plan = build_replay_plan(proof_ready, binary_path=tmp_path / "marker.sh", mode="native")

    assert plan.entries == ()


def test_semantic_boosted_deterministic_target_gets_one_selected_replay(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {"cmd.c": "void cmd(char **argv){ system(argv[1]); }\n"},
        string_refs={"cmd.c": ["ping"]},
    )
    run_semantic_seed_stage(export_dir, tmp_path / "semantic", provider=SemanticProvider(), classes=["command_injection"])
    base = [
        CandidateState(
            candidate_id="static-command",
            vulnerability_type="command_injection",
            status=CandidateStatus.PROOF_READY.value,
            target={"path": str(tmp_path / "marker.sh")},
            location={"function_name": "cmd", "address": "0x1000"},
            source={"kind": "argv", "expression": "argv[1]"},
            sink={"name": "system"},
            type_facts={"path_is_valid": True, "input_reaches_sink": True},
            proof_obligations=[],
            blockers=[],
            metadata={"source_model": "StaticCandidate"},
        )
    ]
    states = semantic_seed_candidates_from_artifacts(tmp_path / "semantic", base_states=base, binary_path=tmp_path / "marker.sh")

    plan = build_replay_plan(states, binary_path=tmp_path / "marker.sh", mode="native")

    assert len(states) == 1
    assert sum(1 for entry in plan.entries if entry.selected) == 1
    assert all(entry.provenance == "deterministic" for entry in plan.entries)


def test_fs_config_memory_seed_enriches_matching_deterministic_memory_candidates(tmp_path: Path) -> None:
    semantic_dir = tmp_path / "semantic"
    accepted_dir = semantic_dir / "accepted"
    accepted_dir.mkdir(parents=True)
    seed_path = accepted_dir / "seed.json"
    seed_path.write_text(
        json.dumps(
            {
                "accepted": True,
                "seed_id": "seed-1",
                "vulnerability_type": "fs_config_memory_corruption",
                "cluster_id": "cluster-1",
                "location": {"function_name": "FUN_1000", "address": "0x1000"},
                "sink": {"name": "config file writer"},
                "source": {"kind": "config"},
                "replay_hints": {
                    "mode": "qemu_user|native",
                    "expected_result": {"proof_oracle": {"kind": "fs_config_memory_corruption_oracle"}},
                },
            }
        )
    )
    base = [
        CandidateState(
            candidate_id=f"static-{index}",
            vulnerability_type="stack_overflow",
            status=CandidateStatus.PROOF_READY.value,
            target={},
            location={"function_name": "FUN_1000", "address": "0x1000"},
            source={},
            sink={"name": "strcat"},
            type_facts={},
            proof_obligations=[],
            blockers=[],
            metadata={"source_model": "StaticCandidate"},
        )
        for index in range(2)
    ]

    states = semantic_seed_candidates_from_artifacts(semantic_dir, base_states=base, binary_path=tmp_path / "demo")

    assert len(states) == 2
    assert {state.metadata["semantic_seed_id"] for state in states} == {"seed-1"}
    assert all(state.metadata["semantic_enrichment_only"] is True for state in states)
    assert all("replay_hints" not in state.type_facts for state in states)
    plan = build_replay_plan(states, binary_path=tmp_path / "demo", mode="qemu_user", max_requests_per_candidate=1)
    assert not any(entry.provenance == "llm_semantic_seed" for entry in plan.entries)


def test_replay_plan_keeps_distinct_unresolved_local_sink_offsets(tmp_path: Path) -> None:
    states = [
        CandidateState(
            candidate_id=f"demo:0x1000:FUN_1000:{line}:strcpy:local_20:{offset}:unbounded",
            vulnerability_type="heap_overflow",
            status=CandidateStatus.PROOF_READY.value,
            target={"path": str(tmp_path / "demo")},
            location={"function_name": "FUN_1000", "address": "0x1000"},
            source={},
            sink={"name": "strcpy", "target_buffer": "local_20"},
            type_facts={
                "static_candidate": {
                    "address": "0x1000",
                    "operation_address": "0x1000",
                    "sink": "strcpy",
                    "target_buffer": "local_20",
                    "offset_expr": offset,
                    "line_number": line,
                    "destination_kind": "heap",
                    "write_relation": "unbounded",
                    "capacity_model": {"symbolic_expr": "strlen(param_1)+strlen(param_2)+2"},
                }
            },
            proof_obligations=[],
            blockers=[],
            metadata={"source_model": "StaticCandidate"},
        )
        for line, offset in ((30, "0"), (40, "local_24"))
    ]

    plan = build_replay_plan(states, binary_path=tmp_path / "demo", mode="native")
    selected = [entry.candidate_id for entry in plan.entries if entry.selected]

    assert selected == [
        "demo:0x1000:FUN_1000:30:strcpy:local_20:0:unbounded",
        "demo:0x1000:FUN_1000:40:strcpy:local_20:local_24:unbounded",
    ]
    assert not any(entry.reason == "duplicate_proof_obligation" for entry in plan.entries)


def test_fs_config_memory_class_is_provider_free_deterministic_enrichment(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {
            "cfg.c": (
                "void cfg(void){ getInteger(\"P1\",0); getString(\"P2\",0); "
                "operator_new(1); snprintf(buf,0x80,\"%s\",value); ofstream(\"/tmp/x\"); }"
            )
        },
    )

    class CountingProvider:
        calls = 0

        def generate(self, pack: Mapping[str, Any], *, phase: str, vuln_class: str) -> Mapping[str, Any]:
            self.calls += 1
            raise AssertionError("memory enrichment must not call the semantic provider")

    provider = CountingProvider()

    result = run_semantic_seed_stage(
        export_dir,
        tmp_path / "semantic",
        provider=provider,
        classes=["fs_config_memory_corruption"],
        max_clusters_per_class=1,
        max_zoom_seeds=1,
    )

    assert result.summary["accepted_count"] == 1
    assert result.summary["rejected_count"] == 0
    assert result.summary["provider_calls"] == 0
    assert result.summary["funnel_metrics"]["memory_semantic_feature_count"] == 1
    assert provider.calls == 0
    accepted = json.loads(next((tmp_path / "semantic" / "accepted").glob("*.json")).read_text())
    assert accepted["vulnerability_type"] == "fs_config_memory_corruption"
    assert accepted["sink"]["name"] == "snprintf"
    assert accepted["replay_hints"] == {}
    assert accepted["deterministic_enrichment_only"] is True
    assert semantic_seed_candidates_from_artifacts(tmp_path / "semantic", binary_path=tmp_path / "demo") == []

    base = [
        CandidateState(
            candidate_id="static-cfg",
            vulnerability_type="stack_overflow",
            status=CandidateStatus.PROOF_READY.value,
            target={},
            location={"function_name": "cfg", "address": "0x1000"},
            source={},
            sink={"name": "snprintf"},
            type_facts={},
            proof_obligations=[],
            blockers=[],
            metadata={"source_model": "StaticCandidate"},
        )
    ]
    states = semantic_seed_candidates_from_artifacts(tmp_path / "semantic", base_states=base, binary_path=tmp_path / "demo")

    assert states[0].metadata["semantic_enrichment_only"] is True
    assert states[0].type_facts["semantic_memory_enrichment"]["seed_id"] == accepted["seed_id"]

    disabled_result = run_semantic_seed_stage(
        export_dir,
        tmp_path / "semantic_no_provider",
        classes=["fs_config_memory_corruption"],
        max_clusters_per_class=1,
    )
    assert disabled_result.summary["enabled"] is False
    assert disabled_result.summary["accepted_count"] == 1
    assert disabled_result.summary["accepted_target_count"] == 0


def test_semantic_seed_dedupes_targets_and_caps_per_function_class(tmp_path: Path) -> None:
    export_dir = _write_export(
        tmp_path,
        {"cmd.c": "void cmd(char **argv){ system(argv[1]); popen(argv[2], \"r\"); }\n"},
        string_refs={"cmd.c": ["/bin/sh"]},
    )

    class NoisyProvider:
        def generate(self, pack: Mapping[str, Any], *, phase: str, vuln_class: str) -> Mapping[str, Any]:
            if phase == "cluster_triage":
                return {"accepted_clusters": [{"cluster_id": pack["clusters"][0]["cluster_id"]}], "cost_metadata": {"model_calls": 1}}
            cluster = pack["cluster"]
            anchor = cluster["anchors"][0]
            signal = cluster["string_signal"]
            common = {
                "vulnerability_type": vuln_class,
                "cluster_id": cluster["cluster_id"],
                "string_signal_id": signal["signal_id"],
                "string_anchor": signal["anchor"],
                "anchors": [anchor],
                "source": {"kind": "argv", "expression": "argv[1]"},
                "proof_oracle": {"kind": "command_effect", "marker": "SEMANTIC_MARKER"},
                "replay_hints": {
                    "mode": "native",
                    "expected_result": {"proof_oracle": {"kind": "command_effect", "marker": "SEMANTIC_MARKER"}},
                },
            }
            return {
                "seeds": [
                    {**common, "sink": {"name": "system"}},
                    {**common, "sink": {"name": "system"}},
                    {**common, "sink": {"name": "popen"}},
                ],
                "cost_metadata": {"model_calls": 1},
            }

    result = run_semantic_seed_stage(
        export_dir,
        tmp_path / "semantic_noisy",
        provider=NoisyProvider(),
        classes=["command_injection"],
        max_clusters_per_class=1,
        max_seeds_per_function_class=1,
    )
    rejected_reasons = [row["failure_reason"] for row in json.loads(result.rejected_index_path.read_text())["rejected"]]

    assert result.summary["accepted_count"] == 1
    assert any("duplicate_semantic_target" in reason for reason in rejected_reasons)
    assert any("per_function_class_seed_cap" in reason for reason in rejected_reasons)


def test_blocked_only_hypothesis_policy_skips_candidates_with_replay_plan(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    candidate_id = "has-replay"
    pack = {
        "candidate_id": candidate_id,
        "candidate": {
            "candidate_id": candidate_id,
            "vulnerability_type": "command_injection",
            "location": {"function_name": "cmd", "address": "0x1000"},
            "sink": {"name": "system"},
        },
    }
    (evidence_dir / "pack.json").write_text(json.dumps(pack))
    (evidence_dir / "index.json").write_text(json.dumps({"evidence_packs": [{"candidate_id": candidate_id, "path": "pack.json"}]}))
    state = CandidateState(
        candidate_id=candidate_id,
        vulnerability_type="command_injection",
        status=CandidateStatus.PROOF_READY.value,
        target={"path": "/tmp/demo"},
        location={"function_name": "cmd", "address": "0x1000"},
        source={},
        sink={"name": "system"},
        type_facts={"path_is_valid": True},
        proof_obligations=[],
        blockers=[],
    )
    replay_plan = build_replay_plan(
        [state],
        binary_path=tmp_path / "demo",
        mode="function_harness",
    )

    class CountingProvider:
        calls = 0

        def generate(self, evidence_pack: Mapping[str, Any], *, system: str) -> Mapping[str, Any]:
            self.calls += 1
            return {}

    provider = CountingProvider()
    result = run_hypothesis_stage(
        evidence_dir,
        tmp_path / "hypotheses",
        provider=provider,
        systems=["L2"],
        candidate_states=[state],
        replay_plan=replay_plan,
    )

    assert provider.calls == 0
    assert result.summary["eligible_candidate_count"] == 0
    assert result.summary["skipped_candidates"][0]["reason"] == "concrete_replay_plan_exists"


def test_non_crashing_command_and_filesystem_oracles_confirm_with_observation(tmp_path: Path) -> None:
    command_script = tmp_path / "command.sh"
    command_script.write_text("#!/bin/sh\necho SEMANTIC_MARKER\n")
    command_script.chmod(0o755)
    command = ReplayRequest(
        candidate_id="cmd-effect",
        mode="native",
        setup={"binary_path": str(command_script)},
        input={},
        expected_result={"proof_oracle": {"kind": "command_effect", "marker": "SEMANTIC_MARKER"}},
    )

    command_result = run_replay_request(command, tmp_path / "replay")

    assert command_result.result == "confirmed"
    assert command_result.crash_observed is False
    assert any(path.endswith("dynamic_command_effect_observation.json") for path in command_result.artifacts)

    read_script = tmp_path / "read.sh"
    read_script.write_text("#!/bin/sh\necho ESCAPED_READ\n")
    read_script.chmod(0o755)
    read_request = ReplayRequest(
        candidate_id="read-escape",
        mode="native",
        setup={"binary_path": str(read_script)},
        input={},
        expected_result={"proof_oracle": {"kind": "filesystem_read_escape", "marker": "ESCAPED_READ"}},
    )
    assert run_replay_request(read_request, tmp_path / "replay").result == "confirmed"

    proof_file = tmp_path / "escaped_write.txt"
    write_script = tmp_path / "write.sh"
    write_script.write_text("#!/bin/sh\nprintf ESCAPED_WRITE > \"$1\"\n")
    write_script.chmod(0o755)
    write_request = ReplayRequest(
        candidate_id="write-escape",
        mode="native",
        setup={"binary_path": str(write_script)},
        input={"argv": [str(proof_file)]},
        expected_result={"proof_oracle": {"kind": "filesystem_write_escape", "marker": "ESCAPED_WRITE", "target_path": str(proof_file)}},
    )
    write_result = run_replay_request(write_request, tmp_path / "replay")

    assert write_result.result == "confirmed"
    assert any(path.endswith("dynamic_filesystem_write_escape_observation.json") for path in write_result.artifacts)

    format_probe = "FORMAT_PROBE_%x_END"
    format_script = tmp_path / "format.sh"
    format_script.write_text("#!/bin/sh\nprintf \"$1\"\n")
    format_script.chmod(0o755)
    format_request = ReplayRequest(
        candidate_id="format-string",
        mode="native",
        setup={"binary_path": str(format_script)},
        input={"argv": [format_probe]},
        expected_result={
            "proof_oracle": {
                "kind": "format_string_effect",
                "marker": format_probe,
                "format_directive": "%x",
                "syscall_observation": False,
            }
        },
    )
    format_result = run_replay_request(format_request, tmp_path / "replay")

    assert format_result.result == "confirmed"
    assert any(path.endswith("dynamic_format_string_effect_observation.json") for path in format_result.artifacts)

    safe_format_script = tmp_path / "safe_format.sh"
    safe_format_script.write_text("#!/bin/sh\nprintf '%s' \"$1\"\n")
    safe_format_script.chmod(0o755)
    safe_format_request = ReplayRequest(
        candidate_id="safe-format-string",
        mode="native",
        setup={"binary_path": str(safe_format_script)},
        input={"argv": [format_probe]},
        expected_result=format_request.expected_result,
    )

    assert run_replay_request(safe_format_request, tmp_path / "safe-replay").result == "sink_reached_no_bug"


def test_credential_and_auth_oracles_require_observed_effect(tmp_path: Path) -> None:
    credential_script = tmp_path / "credential.sh"
    credential_script.write_text("#!/bin/sh\necho 'password=SECRET_TOKEN'\n")
    credential_script.chmod(0o755)
    credential_request = ReplayRequest(
        candidate_id="credential-disclosure",
        mode="native",
        setup={"binary_path": str(credential_script)},
        input={},
        expected_result={"proof_oracle": {"kind": "credential_disclosure", "secret_token": "SECRET_TOKEN"}},
    )

    credential_result = run_replay_request(credential_request, tmp_path / "replay")

    assert credential_result.result == "confirmed"
    assert credential_result.bug_observed is True
    assert any(path.endswith("dynamic_credential_disclosure_observation.json") for path in credential_result.artifacts)

    safe_credential_script = tmp_path / "safe_credential.sh"
    safe_credential_script.write_text("#!/bin/sh\necho 'redacted'\n")
    safe_credential_script.chmod(0o755)
    safe_credential = ReplayRequest(
        candidate_id="safe-credential-disclosure",
        mode="native",
        setup={"binary_path": str(safe_credential_script)},
        input={},
        expected_result=credential_request.expected_result,
    )
    assert run_replay_request(safe_credential, tmp_path / "safe-replay").result != "confirmed"

    auth_script = tmp_path / "auth.sh"
    auth_script.write_text("#!/bin/sh\necho 'role=admin; ADMIN_OK'\n")
    auth_script.chmod(0o755)
    auth_request = ReplayRequest(
        candidate_id="auth-bypass",
        mode="native",
        setup={"binary_path": str(auth_script)},
        input={},
        expected_result={"proof_oracle": {"kind": "auth_bypass_effect", "success_marker": "ADMIN_OK"}},
    )

    auth_result = run_replay_request(auth_request, tmp_path / "replay")

    assert auth_result.result == "confirmed"
    assert auth_result.bug_observed is True
    assert any(path.endswith("dynamic_auth_bypass_effect_observation.json") for path in auth_result.artifacts)

    safe_auth_script = tmp_path / "safe_auth.sh"
    safe_auth_script.write_text("#!/bin/sh\necho 'login failed'\n")
    safe_auth_script.chmod(0o755)
    safe_auth = ReplayRequest(
        candidate_id="safe-auth-bypass",
        mode="native",
        setup={"binary_path": str(safe_auth_script)},
        input={},
        expected_result=auth_request.expected_result,
    )
    assert run_replay_request(safe_auth, tmp_path / "safe-auth-replay").result != "confirmed"


def test_auto_built_format_string_request_uses_probe_and_oracle(tmp_path: Path) -> None:
    binary = tmp_path / "format.sh"
    binary.write_text("#!/bin/sh\nprintf \"$1\"\n")
    binary.chmod(0o755)
    state = CandidateState(
        candidate_id="format-auto",
        vulnerability_type="format_string",
        status=CandidateStatus.PROOF_READY.value,
        target={"path": str(binary), "binary": binary.name},
        location={"function_name": "main", "address": "0x1200"},
        source={"kind": "format_expression", "expression": "argv[1]"},
        sink={"name": "printf", "kind": "format_parser"},
        type_facts={"format_arg": "argv[1]"},
        proof_obligations=[],
        blockers=[],
    )

    request = build_replay_requests([state], binary_path=binary, mode="native")[0]
    result = run_replay_request(request, tmp_path / "replay")

    assert request.input["input_model"] == "argv"
    assert "%x" in request.input["argv"][0]
    assert request.expected_result["proof_oracle"]["kind"] == "format_string_effect"
    assert request.expected_result["proof_oracle"]["marker"] == request.input["argv"][0]
    assert result.result == "confirmed"
    assert result.bug_observed is True


def test_native_socket_service_replay_confirms_socket_observed_effect(tmp_path: Path) -> None:
    port = _free_tcp_port()
    server = tmp_path / "socket_service.py"
    server.write_text(
        "#!/usr/bin/env python3\n"
        "import socket, sys\n"
        "port = int(sys.argv[1])\n"
        "sock = socket.socket()\n"
        "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "sock.bind(('127.0.0.1', port))\n"
        "sock.listen(1)\n"
        "conn, _addr = sock.accept()\n"
        "data = conn.recv(4096)\n"
        "if b'SOCKET_PROBE' in data:\n"
        "    conn.sendall(b'SOCKET_EFFECT_OBSERVED\\n')\n"
        "conn.close()\n"
        "sock.close()\n"
    )
    server.chmod(0o755)
    request = ReplayRequest(
        candidate_id="socket-service-effect",
        mode="native",
        setup={"binary_path": str(server), "sink": "recv", "timeout_seconds": 5.0},
        input={"input_model": "socket_service", "argv": [str(port)], "port": port, "payload": "SOCKET_PROBE\n"},
        expected_result={"proof_oracle": {"kind": "command_effect", "marker": "SOCKET_EFFECT_OBSERVED"}},
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "confirmed"
    assert result.sink_reached is True
    assert result.bug_observed is True
    assert "SOCKET_EFFECT_OBSERVED" in result.control_result["socket_response"]


def test_native_socket_service_materializes_port_env_and_line_payload(tmp_path: Path) -> None:
    server = tmp_path / "socket_service_env.py"
    server.write_text(
        "#!/usr/bin/env python3\n"
        "import os, socket, time\n"
        "port = int(os.environ['REPLAY_PORT'])\n"
        "sock = socket.socket()\n"
        "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "sock.bind(('127.0.0.1', port))\n"
        "sock.listen(1)\n"
        "conn, _addr = sock.accept()\n"
        "data = conn.recv(4096)\n"
        "if data == b'SOCKET_PROBE\\n':\n"
        "    conn.sendall(b'SOCKET_ENV_EFFECT\\n')\n"
        "conn.close()\n"
        "sock.close()\n"
    )
    server.chmod(0o755)
    request = ReplayRequest(
        candidate_id="socket-service-env-port",
        mode="native",
        setup={"binary_path": str(server), "sink": "recv", "timeout_seconds": 5.0},
        input={"input_model": "socket_service", "port_env": "REPLAY_PORT", "payload": "SOCKET_PROBE", "protocol": "line"},
        expected_result={"proof_oracle": {"kind": "command_effect", "marker": "SOCKET_ENV_EFFECT"}},
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "confirmed"
    assert result.control_result["socket_service"]["port"] > 0
    assert result.control_result["socket_response"] == "SOCKET_ENV_EFFECT\n"


def test_native_socket_service_without_endpoint_materialization_is_blocked(tmp_path: Path) -> None:
    server = tmp_path / "socket_service_missing_port.py"
    server.write_text("#!/usr/bin/env python3\n")
    server.chmod(0o755)
    request = ReplayRequest(
        candidate_id="socket-service-missing-port",
        mode="native",
        setup={"binary_path": str(server), "sink": "recv"},
        input={"input_model": "socket_service", "payload": "SOCKET_PROBE"},
        expected_result={"proof_oracle": {"kind": "command_effect", "marker": "SOCKET_EFFECT_OBSERVED"}},
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "blocked"
    assert "concrete TCP port or deterministic port materialization" in result.control_result["reason"]
    service_artifacts = [Path(path) for path in result.artifacts if Path(path).name == "service_replay_result.json"]
    assert service_artifacts
    service_payload = json.loads(service_artifacts[0].read_text())
    assert service_payload["artifact_kind"] == "service_replay_result"
    assert service_payload["status"] == "blocked"
    assert service_payload["blockers"] == ["missing_service_endpoint"]
    assert any(str(path).endswith("request.json") for path in service_payload["artifacts"])


def test_service_replay_result_records_named_blocker_codes(tmp_path: Path) -> None:
    request = ReplayRequest(
        candidate_id="service-blocker-taxonomy",
        mode="native",
        setup={},
        input={"input_model": "http_daemon", "path": "/diag"},
        expected_result={},
    )
    examples = {
        "missing rootfs for service replay": "missing_rootfs",
        "missing config file for service replay": "missing_config",
        "unsupported event loop model": "unsupported_event_loop",
        "unresolved route handler for /diag": "unresolved_route_handler",
        "service replay timed out waiting for readiness": "timeout",
        "unsupported architecture: armel qemu unavailable": "unsupported_architecture",
    }

    for index, (reason, expected) in enumerate(examples.items()):
        candidate_dir = tmp_path / f"case-{index}"
        candidate_dir.mkdir()
        (candidate_dir / "request.json").write_text(json.dumps(request.to_dict(), indent=2, sort_keys=True))

        artifact_path = replay_runners._write_service_replay_result(request, candidate_dir, blocker=reason)

        payload = json.loads(artifact_path.read_text())
        assert payload["artifact_kind"] == "service_replay_result"
        assert payload["status"] == "blocked"
        assert payload["blocked_reason"] == reason
        assert payload["blockers"] == [expected]
        assert any(str(path).endswith("request.json") for path in payload["artifacts"])


def test_auto_built_socket_service_request_carries_endpoint_materialization_facts(tmp_path: Path) -> None:
    binary = tmp_path / "daemon.sh"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    state = CandidateState(
        candidate_id="socket-auto-materialization",
        vulnerability_type="command_injection",
        status=CandidateStatus.PROOF_READY.value,
        target={"path": str(binary), "binary": binary.name},
        location={"function_name": "handle_client", "address": "0x1200"},
        source={"kind": "socket", "expression": "recv"},
        sink={"name": "system", "kind": "command_execution"},
        type_facts={
            "process_input": {
                "input_model": "socket_service",
                "socket_service": {
                    "port_env": "REPLAY_PORT",
                    "protocol": "line",
                    "request_terminator": "\n",
                },
            }
        },
        proof_obligations=[],
        blockers=[],
    )

    request = build_replay_requests([state], binary_path=binary, mode="native")[0]

    assert request.input["input_model"] == "socket_service"
    assert request.input["port_env"] == "REPLAY_PORT"
    assert request.input["protocol"] == "line"
    assert request.input["request_terminator"] == "\n"


def test_native_http_daemon_replay_confirms_http_response_effect(tmp_path: Path) -> None:
    server = tmp_path / "http_daemon.py"
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    server.write_text(
        "#!/usr/bin/env python3\n"
        "import os, socket, time\n"
        "port = int(os.environ['REPLAY_PORT'])\n"
        "sock = socket.socket()\n"
        "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "sock.bind(('127.0.0.1', port))\n"
        "sock.listen(1)\n"
        "conn, _addr = sock.accept()\n"
        "request = conn.recv(8192).decode('latin-1', 'replace')\n"
        "if 'GET /diag?cmd=echo+HTTP_DAEMON_EFFECT HTTP/1.0' in request:\n"
        "    body = b'HTTP_DAEMON_EFFECT\\n'\n"
        "else:\n"
        "    body = b'miss\\n'\n"
        "conn.sendall(b'HTTP/1.0 200 OK\\r\\nContent-Length: ' + str(len(body)).encode() + b'\\r\\n\\r\\n' + body)\n"
        "conn.close()\n"
        "time.sleep(10)\n"
        "sock.close()\n"
    )
    server.chmod(0o755)
    request = ReplayRequest(
        candidate_id="http-daemon-effect",
        mode="native",
        setup={
            "binary_path": str(server),
            "rootfs_path": str(rootfs),
            "startup_command": "python3 http_daemon.py",
            "sink": "httpd_parse_request",
            "timeout_seconds": 5.0,
            "env": {"FIRMWARE_PROFILE": "test"},
            "config": {"httpd.conf": "Listen ${REPLAY_PORT}"},
            "routes": [{"method": "GET", "path": "/diag"}],
        },
        input={
            "input_model": "http_daemon",
            "port_env": "REPLAY_PORT",
            "method": "GET",
            "path": "/diag",
            "query": {"cmd": "echo HTTP_DAEMON_EFFECT"},
        },
        expected_result={"proof_oracle": {"kind": "command_effect", "marker": "HTTP_DAEMON_EFFECT"}},
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "confirmed"
    assert result.bug_observed is True
    assert result.crash_observed is False
    assert result.control_result["replay_terminated_process"] is True
    assert result.control_result["socket_service"]["input_model"] == "http_daemon"
    assert "HTTP_DAEMON_EFFECT" in result.control_result["http_response"]
    service_artifacts = [Path(path) for path in result.artifacts if Path(path).name == "service_replay_result.json"]
    assert service_artifacts
    service_payload = json.loads(service_artifacts[0].read_text())
    assert service_payload["artifact_kind"] == "service_replay_result"
    assert service_payload["status"] == "confirmed"
    assert service_payload["input_model"] == "http_daemon"
    assert service_payload["request"]["method"] == "GET"
    assert service_payload["request"]["path"] == "/diag"
    assert service_payload["environment"]["rootfs_path"] == str(rootfs)
    assert service_payload["environment"]["startup_command"] == "python3 http_daemon.py"
    assert service_payload["environment"]["route_count"] == 1
    assert service_payload["environment"]["config_keys"] == ["httpd.conf"]
    assert "FIRMWARE_PROFILE" in service_payload["environment"]["env_keys"]
    assert "REPLAY_PORT" in service_payload["environment"]["env_keys"]
    assert any(str(path).endswith("native_transcript.json") for path in service_payload["artifacts"])


def test_deterministic_http_daemon_plan_uses_process_input_facts(tmp_path: Path) -> None:
    binary = tmp_path / "httpd.sh"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    state = CandidateState(
        candidate_id="auto-http-daemon",
        vulnerability_type="command_injection",
        status=CandidateStatus.PROOF_READY.value,
        target={"path": str(binary), "binary": binary.name},
        location={"function_name": "handle_http", "address": "0x1200"},
        source={"kind": "http_route", "expression": "/diag", "input_model": "http_daemon"},
        sink={"name": "system", "kind": "command_execution"},
        type_facts={
            "process_input": {
                "input_model": "http_daemon",
                "http_daemon": {
                    "port_env": "REPLAY_PORT",
                    "method": "GET",
                    "path": "/diag",
                },
            },
            "proof_oracle": {"kind": "command_effect", "marker": "HTTP_DAEMON_EFFECT"},
            "replay_hints": {"input": {"query": {"cmd": "echo HTTP_DAEMON_EFFECT"}}},
        },
        proof_obligations=[],
        blockers=[],
    )

    plan = build_replay_plan([state], binary_path=binary, mode="native")
    entries = [entry for entry in plan.entries if entry.provenance == "deterministic_http_daemon"]

    assert len(entries) == 1
    assert entries[0].selected is True
    assert entries[0].request.input["input_model"] == "http_daemon"
    assert entries[0].request.input["port_env"] == "REPLAY_PORT"
    assert entries[0].request.input["path"] == "/diag"
    assert entries[0].request.expected_result["process_input_model"] == "http_daemon"


def test_generic_http_daemon_memory_replay_requires_explicit_payload_placement(tmp_path: Path) -> None:
    binary = tmp_path / "httpd.sh"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    state = CandidateState(
        candidate_id="http-memory-ambiguous",
        vulnerability_type="stack_overflow",
        status=CandidateStatus.PROOF_READY.value,
        target={"path": str(binary), "binary": binary.name},
        location={"function_name": "handle_http", "address": "0x1200"},
        source={"kind": "http_route", "input_model": "http_daemon"},
        sink={"name": "strcpy", "target_buffer": "buf"},
        type_facts={
            "capacity_bytes": 16,
            "process_input": {
                "input_model": "http_daemon",
                "http_daemon": {"port_env": "REPLAY_PORT", "method": "GET", "path": "/diag"},
            },
        },
        proof_obligations=[],
        blockers=[],
    )

    requests = build_replay_requests([state], binary_path=binary, mode="native")

    assert len(requests) == 1
    assert requests[0].mode == "off"
    assert requests[0].setup["blocked_reason"] == "ambiguous_http_replay_requires_llm:missing_explicit_input_surface"


def test_native_syslog_interposer_confirms_format_string_effect(tmp_path: Path) -> None:
    compiler = shutil.which("gcc") or shutil.which("cc")
    if not compiler:
        pytest.skip("host C compiler required for native syslog interposer replay")
    source = tmp_path / "syslog_format.c"
    binary = tmp_path / "syslog_format"
    source.write_text(
        "#include <syslog.h>\n"
        "int main(int argc, char **argv) {\n"
        "  if (argc > 1) syslog(LOG_ERR, argv[1]);\n"
        "  return 0;\n"
        "}\n"
    )
    completed = subprocess.run([compiler, "-O0", "-g0", "-o", str(binary), str(source)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    probe = "SYSLOG_FMT_%x_END"
    request = ReplayRequest(
        candidate_id="syslog-format",
        mode="native",
        setup={"binary_path": str(binary), "sink": "syslog"},
        input={"argv": [probe]},
        expected_result={
            "proof_oracle": {
                "kind": "format_string_effect",
                "marker": probe,
                "format_directive": "%x",
                "sink": "syslog",
                "syslog_observation": True,
            }
        },
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "confirmed"
    assert result.bug_observed is True
    assert "SYSLOG_FMT_" in result.control_result["syslog"]
    assert "%x" not in result.control_result["syslog"]


def test_native_syslog_observation_blocks_static_elf_targets(tmp_path: Path) -> None:
    binary = tmp_path / "static_elf"
    data = bytearray(64 + 56)
    data[0:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    struct.pack_into("<H", data, 16, 2)
    struct.pack_into("<H", data, 18, 62)
    struct.pack_into("<I", data, 20, 1)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<H", data, 52, 64)
    struct.pack_into("<H", data, 54, 56)
    struct.pack_into("<H", data, 56, 1)
    struct.pack_into("<I", data, 64, 1)
    binary.write_bytes(data)
    binary.chmod(0o755)
    request = ReplayRequest(
        candidate_id="syslog-static",
        mode="native",
        setup={"binary_path": str(binary), "sink": "syslog"},
        input={"argv": ["SYSLOG_FMT_%x_END"]},
        expected_result={
            "proof_oracle": {
                "kind": "format_string_effect",
                "marker": "SYSLOG_FMT_%x_END",
                "format_directive": "%x",
                "sink": "syslog",
                "syslog_observation": True,
            }
        },
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "setup_invalid"
    assert "static ELF cannot be observed with LD_PRELOAD" in result.control_result["reason"]


def test_qemu_user_syslog_observation_is_explicitly_blocked(tmp_path: Path) -> None:
    binary = tmp_path / "syslog.sh"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    request = ReplayRequest(
        candidate_id="syslog-qemu-user",
        mode="qemu_user",
        setup={"binary_path": str(binary), "sink": "syslog"},
        input={"argv": ["SYSLOG_FMT_%x_END"]},
        expected_result={
            "proof_oracle": {
                "kind": "format_string_effect",
                "marker": "SYSLOG_FMT_%x_END",
                "format_directive": "%x",
                "sink": "syslog",
                "syslog_observation": True,
            }
        },
    )

    result = run_replay_request(request, tmp_path / "replay")

    assert result.result == "blocked"
    assert "qemu_user syslog observation is unsupported" in result.control_result["reason"]


def test_http_cgi_native_replay_sets_env_body_and_confirms_semantic_oracles(tmp_path: Path) -> None:
    command_script = tmp_path / "cgi_command.sh"
    command_script.write_text(
        "#!/bin/sh\n"
        "body=$(cat)\n"
        "if [ \"$REQUEST_METHOD\" = POST ] && [ \"$SCRIPT_NAME\" = /cgi-bin/demo ] && printf '%s' \"$body\" | grep -q 'cmd=id'; then\n"
        "  echo 'uid=1000(cgi)'\n"
        "fi\n"
    )
    command_script.chmod(0o755)
    command = ReplayRequest(
        candidate_id="http-cgi-command",
        mode="native",
        setup={"binary_path": str(command_script), "routes": [{"method": "POST", "path": "/cgi-bin/demo"}]},
        input={"input_model": "http_cgi", "form": {"cmd": "id"}, "cookies": {"session": "abc"}},
        expected_result={"proof_oracle": {"kind": "command_effect", "marker": "uid=1000"}},
    )
    command_result = run_replay_request(command, tmp_path / "replay")
    command_transcript = json.loads(Path(next(path for path in command_result.artifacts if path.endswith("native_transcript.json"))).read_text())

    assert command_result.result == "confirmed"
    assert command_transcript["target_env"]["REQUEST_METHOD"] == "POST"
    assert command_transcript["target_env"]["SCRIPT_NAME"] == "/cgi-bin/demo"
    assert command_transcript["target_env"]["CONTENT_LENGTH"] == str(len("cmd=id"))
    assert command_transcript["target_env"]["HTTP_COOKIE"] == "session=abc"

    read_script = tmp_path / "cgi_read.sh"
    read_script.write_text(
        "#!/bin/sh\n"
        "case \"$QUERY_STRING\" in\n"
        "  *..%2Fetc%2Fpasswd*|*../etc/passwd*) echo 'root:x:0:0:root:/root:/bin/sh' ;;\n"
        "esac\n"
    )
    read_script.chmod(0o755)
    read_request = ReplayRequest(
        candidate_id="http-cgi-read",
        mode="native",
        setup={"binary_path": str(read_script), "routes": [{"method": "GET", "path": "/cgi-bin/read"}]},
        input={"input_model": "http_cgi", "method": "GET", "query": {"file": "../etc/passwd"}},
        expected_result={"proof_oracle": {"kind": "filesystem_read_escape", "marker": "root:x"}},
    )
    assert run_replay_request(read_request, tmp_path / "replay").result == "confirmed"

    proof_file = tmp_path / "escaped_write.txt"
    write_script = tmp_path / "cgi_write.sh"
    write_script.write_text("#!/bin/sh\ncat >/dev/null\nprintf ESCAPED_WRITE > \"$FORM_path\"\n")
    write_script.chmod(0o755)
    write_request = ReplayRequest(
        candidate_id="http-cgi-write",
        mode="native",
        setup={"binary_path": str(write_script), "routes": [{"method": "POST", "path": "/cgi-bin/write"}]},
        input={"input_model": "http_cgi", "form": {"path": str(proof_file)}},
        expected_result={
            "proof_oracle": {
                "kind": "filesystem_write_escape",
                "marker": "ESCAPED_WRITE",
                "target_path": str(proof_file),
            }
        },
    )
    write_result = run_replay_request(write_request, tmp_path / "replay")

    assert write_result.result == "confirmed"
    assert proof_file.read_text() == "ESCAPED_WRITE"


def _http_cgi_candidate(
    binary_path: Path,
    *,
    candidate_id: str = "auto-http-cgi",
    vulnerability_type: str = "command_injection",
    route: str = "/cgi-bin/demo",
    method: str = "POST",
    input_model: str = "http_cgi",
    surface_kind: str = "cgi_handler",
    proof_oracle: Mapping[str, Any] | None = None,
    replay_hints: Mapping[str, Any] | None = None,
) -> CandidateState:
    source_trace = {
        "schema_version": 2,
        "status": "complete",
        "attacker_control_reaches_sink_role": True,
        "entry_function": "main",
        "entry_surface_kind": surface_kind,
        "target_function": "handler",
        "target_address": "0x1200",
        "sink_name": "system",
        "call_path": ["main", "handler"],
        "input_model": input_model,
        "argument_roles": [
            {
                "role": "command_argument",
                "expr": "cmd",
                "classification": "source_controlled",
                "controlled": True,
                "complete": True,
            }
        ],
    }
    type_facts: dict[str, Any] = {
        "path_is_valid": True,
        "input_reaches_sink": True,
        "source_to_sink_trace": source_trace,
        "entrypoint_derivation": {
            "status": "derived",
            "input_model": input_model,
            "entry_surface": {
                "function": "main",
                "address": "0x1000",
                "kind": surface_kind,
                "evidence": {
                    "source": "intake_routes",
                    "input_model": input_model,
                    "routes": [
                        {
                            "route": route,
                            "method": method,
                            "path": "/rootfs/etc/httpd.conf",
                            "relative_path": "etc/httpd.conf",
                        }
                    ],
                },
            },
            "source_to_sink_trace": source_trace,
        },
    }
    if proof_oracle is not None:
        type_facts["proof_oracle"] = dict(proof_oracle)
    if replay_hints is not None:
        type_facts["replay_hints"] = dict(replay_hints)
    return CandidateState(
        candidate_id=candidate_id,
        vulnerability_type=vulnerability_type,
        status=CandidateStatus.PROOF_READY.value,
        target={"path": str(binary_path), "binary": binary_path.name},
        location={"function_name": "handler", "address": "0x1200"},
        source={"kind": "route", "expression": route, "input_model": input_model},
        sink={"name": "system", "operation_address": "0x1210"},
        type_facts=type_facts,
        proof_obligations=[],
        blockers=[],
        metadata={"source_model": "StaticCandidate"},
    )


def test_replay_plan_builds_http_cgi_request_from_explicit_replay_intent(tmp_path: Path) -> None:
    binary = tmp_path / "cgi.sh"
    binary.write_text("#!/bin/sh\ncat >/dev/null\necho AUTO_CGI_MARKER\n")
    binary.chmod(0o755)
    state = _http_cgi_candidate(
        binary,
        proof_oracle={"kind": "command_effect", "marker": "AUTO_CGI_MARKER"},
        replay_hints={"input": {"form": {"cmd": "echo AUTO_CGI_MARKER"}}},
    )

    plan = build_replay_plan([state], binary_path=binary, mode="native")
    selected = [entry for entry in plan.entries if entry.selected]

    assert len(selected) == 1
    assert selected[0].provenance == "deterministic_http_cgi"
    request = selected[0].request
    assert request.setup["routes"] == [{"method": "POST", "path": "/cgi-bin/demo"}]
    assert request.setup["process_input_setup"]["input_model"] == "http_cgi"
    assert request.input["input_model"] == "http_cgi"
    assert request.input["form"]["cmd"] == "echo AUTO_CGI_MARKER"
    assert request.expected_result["proof_oracle"]["kind"] == "command_effect"
    assert request.expected_result["proof_oracle"]["marker"] == "AUTO_CGI_MARKER"


def test_replay_plan_routes_ambiguous_http_cgi_to_llm_handoff(tmp_path: Path) -> None:
    binary = tmp_path / "cgi.sh"
    binary.write_text("#!/bin/sh\ncat >/dev/null\n")
    binary.chmod(0o755)
    state = _http_cgi_candidate(
        binary,
        proof_oracle={"kind": "command_effect", "marker": "AUTO_CGI_MARKER"},
    )

    plan = build_replay_plan([state], binary_path=binary, mode="native")
    selected = [entry for entry in plan.entries if entry.selected]

    assert len(selected) == 1
    assert selected[0].request.mode == "off"
    assert selected[0].blocked_reason == "ambiguous_http_replay_requires_llm:missing_explicit_input_surface"
    assert selected[0].request.setup["llm_handoff_required"] is True


def test_replay_plan_does_not_auto_build_generic_http_service_request(tmp_path: Path) -> None:
    binary = tmp_path / "service.sh"
    binary.write_text("#!/bin/sh\ncat >/dev/null\n")
    binary.chmod(0o755)
    state = _http_cgi_candidate(
        binary,
        route="/api/demo",
        input_model="http",
        surface_kind="daemon_launch",
        proof_oracle={"kind": "command_effect", "marker": "AUTO_CGI_MARKER"},
    )

    plan = build_replay_plan([state], binary_path=binary, mode="native")

    assert not any(entry.provenance == "deterministic_http_cgi" for entry in plan.entries)


def test_auto_built_http_cgi_plan_runs_through_native_replay(tmp_path: Path) -> None:
    binary = tmp_path / "cgi_command.sh"
    binary.write_text(
        "#!/bin/sh\n"
        "body=$(cat)\n"
        "if [ \"$REQUEST_METHOD\" = POST ] && [ \"$SCRIPT_NAME\" = /cgi-bin/demo ] && "
        "printf '%s' \"$body\" | grep -q AUTO_CGI_MARKER; then\n"
        "  echo AUTO_CGI_MARKER\n"
        "fi\n"
    )
    binary.chmod(0o755)
    state = _http_cgi_candidate(
        binary,
        proof_oracle={"kind": "command_effect", "marker": "AUTO_CGI_MARKER"},
        replay_hints={"input": {"form": {"cmd": "echo AUTO_CGI_MARKER"}}},
    )
    plan = build_replay_plan([state], binary_path=binary, mode="native")

    results = run_replay_plan(plan, tmp_path / "replay")
    result = results[0]
    transcript = json.loads(
        Path(next(path for path in result.artifacts if path.endswith("native_transcript.json"))).read_text()
    )

    assert result.result == "confirmed"
    assert result.sink_reached is True
    assert result.bug_observed is True
    assert transcript["target_env"]["REQUEST_METHOD"] == "POST"
    assert transcript["target_env"]["SCRIPT_NAME"] == "/cgi-bin/demo"
    assert transcript["target_env"]["FORM_cmd"] == "echo AUTO_CGI_MARKER"
    expected_body = "cmd=echo+AUTO_CGI_MARKER"
    assert transcript["target_env"]["CONTENT_LENGTH"] == str(len(expected_body))


def test_blocked_http_replay_plan_makes_hypothesis_stage_eligible(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    binary = tmp_path / "cgi.sh"
    binary.write_text("#!/bin/sh\ncat >/dev/null\n")
    binary.chmod(0o755)
    state = _http_cgi_candidate(
        binary,
        candidate_id="needs-llm-http",
        proof_oracle={"kind": "command_effect", "marker": "AUTO_CGI_MARKER"},
    )
    pack = {
        "candidate_id": state.candidate_id,
        "candidate": {
            "candidate_id": state.candidate_id,
            "vulnerability_type": state.vulnerability_type,
            "function_name": "handler",
            "sink": "system",
        },
    }
    (evidence_dir / "pack.json").write_text(json.dumps(pack))
    (evidence_dir / "index.json").write_text(
        json.dumps({"evidence_packs": [{"candidate_id": state.candidate_id, "path": "pack.json"}]})
    )
    plan = build_replay_plan([state], binary_path=binary, mode="native")

    class CountingProvider:
        calls = 0

        def generate(self, evidence_pack: Mapping[str, Any], *, system: str) -> Mapping[str, Any]:
            self.calls += 1
            return {}

    provider = CountingProvider()
    result = run_hypothesis_stage(
        evidence_dir,
        tmp_path / "hypotheses",
        provider=provider,
        systems=["L2"],
        candidate_states=[state],
        replay_plan=plan,
    )

    assert provider.calls == 1
    assert result.summary["eligible_candidate_count"] == 1
