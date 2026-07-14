import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from binary_agent.firmware_transactions import (
    FirmwareTransaction,
    FirmwareTransactionSession,
    TransactionTraceAttributor,
    assess_ubus_readiness,
    build_proot_fake_root_command,
    build_transaction_plan,
    compile_qemu_instruction_tracer,
    establish_transaction_readiness,
    inert_payload,
    is_safe_ubus_method,
    parse_ubus_verbose_list,
    publication_acl,
    selected_call_acl,
    validate_targeted_binds,
)


def test_ubus_schema_parsing_and_inert_variants(tmp_path: Path) -> None:
    output = """'network.device' @12345678
\t\"status\":{\"name\":\"String\"}
'network.interface' @abcdef01
\t\"dump\":{}
"""
    schemas = parse_ubus_verbose_list(output)
    assert schemas == {
        "network.device": {"status": {"name": "String"}},
        "network.interface": {"dump": {}},
    }
    assert inert_payload({"name": "String", "count": "Integer", "enabled": "Boolean"}) == {
        "count": 0,
        "enabled": False,
        "name": "",
    }
    binary = tmp_path / "netifd"
    binary.write_bytes(b"fixture")
    plan = build_transaction_plan(target_binary=binary, schemas=schemas, setup_key="shared")
    assert len(plan.transactions) == 3
    status_variants = [item for item in plan.transactions if item.method_name == "status"]
    assert [dict(item.arguments) for item in status_variants] == [{}, {"name": ""}]
    assert status_variants[0].variant_id != status_variants[1].variant_id


def test_unsafe_methods_are_suppressed_and_acl_is_narrow(tmp_path: Path) -> None:
    assert is_safe_ubus_method("getStatus") is True
    assert is_safe_ubus_method("status") is True
    for method in ("set", "add", "remove", "up", "down", "reload", "restart"):
        assert is_safe_ubus_method(method) is False
    binary = tmp_path / "rpcd"
    binary.write_bytes(b"fixture")
    plan = build_transaction_plan(
        target_binary=binary,
        setup_key="rpcd",
        schemas={"session": {"list": {}, "login": {}, "remove": {}}},
    )
    assert [(item.object_name, item.method_name) for item in plan.transactions] == [("session", "list")]
    assert "unsafe_method_suppressed:session:remove" in plan.blockers
    acl = selected_call_acl(plan.transactions, user="tester")
    assert acl == {
        "user": "tester",
        "publish": ["session"],
        "access": {"session": {"methods": ["list"]}},
    }
    discovery = publication_acl(user="tester", object_names=("session",))
    assert discovery["publish"] == ["session"]
    assert set(discovery["access"]["*"]["methods"]) == {"status", "dump", "list", "info"}


def test_broad_proot_binds_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "rpcd"
    source.mkdir()
    with pytest.raises(ValueError, match="broad"):
        validate_targeted_binds({"/usr": source})
    with pytest.raises(ValueError, match="broad"):
        validate_targeted_binds({"/lib": source})
    proot = tmp_path / "proot"
    proot.write_text("#!/bin/sh\n")
    proot.chmod(0o755)
    command = build_proot_fake_root_command(proot, ["/target"], binds={"/usr/lib/rpcd": source})
    assert command[:2] == [str(proot.resolve()), "-0"]
    assert command[-1] == "/target"


def test_readiness_requires_objects_methods_and_supported_schemas() -> None:
    schemas = {"network.interface": {"status": {}, "set": {}}}
    ready = assess_ubus_readiness(
        schemas,
        [("network.interface", "status")],
        required_object_prefixes=("network",),
    )
    assert ready.ready is True
    missing = assess_ubus_readiness(schemas, [("network.interface", "dump")])
    assert missing.ready is False
    assert missing.blockers == ("selected_schema_missing:network.interface:dump",)
    empty = assess_ubus_readiness({}, [])
    assert set(empty.blockers) == {"no_target_objects_published", "no_selected_transactions"}


def test_trace_attribution_excludes_idle_hits(tmp_path: Path) -> None:
    trace = tmp_path / "hits.jsonl"
    brackets = tmp_path / "brackets.jsonl"
    attributor = TransactionTraceAttributor(trace, brackets)
    transaction = FirmwareTransaction.create(
        object_name="network.interface",
        method_name="status",
        schema={},
        arguments={},
        setup_key="netifd",
    )
    with trace.open("a") as handle:
        handle.write(json.dumps({"operation_address": "0x401000"}) + "\n")
        handle.flush()
    start = attributor.begin(transaction)
    with trace.open("a") as handle:
        handle.write(json.dumps({"operation_address": "0x401010"}) + "\n")
        handle.flush()
    attributor.end(transaction, start, returncode=0)
    with trace.open("a") as handle:
        handle.write(json.dumps({"operation_address": "0x401020"}) + "\n")
    rows = attributor.normalize(("0x401000", "0x401010", "0x401020"))
    assert [item["status"] for item in rows] == ["not_observed", "observed", "not_observed"]
    assert {item["operation_address"] for item in attributor.idle_hits()} == {"0x401000", "0x401020"}


def test_execution_readiness_call_and_quiet_baseline_exclude_delayed_startup(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "hits.jsonl"
    brackets = tmp_path / "brackets.jsonl"
    attributor = TransactionTraceAttributor(
        trace,
        brackets,
        require_initialization_baseline=True,
    )
    transaction = FirmwareTransaction.create(
        object_name="network.device",
        method_name="status",
        schema={},
        arguments={},
        setup_key="netifd",
    )
    with pytest.raises(ValueError, match="initialization baseline"):
        attributor.begin(transaction)
    with trace.open("a") as handle:
        handle.write(json.dumps({"operation_address": "0x408f5d"}) + "\n")
        handle.flush()

    def setup_call(_transaction: FirmwareTransaction) -> subprocess.CompletedProcess[str]:
        # Simulate initialization that occurs after object publication while
        # the first client is blocked waiting for the target dispatch loop.
        with trace.open("a") as handle:
            handle.write(json.dumps({"operation_address": "0x40f0f1"}) + "\n")
            handle.write(json.dumps({"operation_address": "0x415ae4"}) + "\n")
            handle.flush()
        return subprocess.CompletedProcess([], 0, "{}", "")

    artifact = tmp_path / "execution-readiness.json"
    barrier = establish_transaction_readiness(
        (transaction,),
        setup_call,
        attributor,
        timeout_seconds=0.2,
        quiet_seconds=0.005,
        poll_seconds=0.001,
        artifact_path=artifact,
    )
    assert barrier["status"] == "observed_ready"
    assert barrier["setup_evidence_only"] is True
    assert artifact.is_file()

    start = attributor.begin(transaction)
    with trace.open("a") as handle:
        handle.write(json.dumps({"operation_address": "0x415ae4"}) + "\n")
        handle.flush()
    attributor.end(transaction, start, returncode=0)
    rows = {
        item["operation_address"]: item
        for item in attributor.normalize(("0x40f0f1", "0x415ae4"))
    }
    assert rows["0x40f0f1"]["status"] == "not_observed"
    assert rows["0x415ae4"]["status"] == "observed"
    startup = attributor.idle_hits()
    assert {item["operation_address"] for item in startup} == {
        "0x408f5d",
        "0x40f0f1",
        "0x415ae4",
    }
    phases = {item["operation_address"]: item["phase"] for item in startup}
    assert phases["0x408f5d"] == "startup_or_setup"
    assert phases["0x40f0f1"] == "readiness_transaction_setup"
    assert phases["0x415ae4"] == "readiness_transaction_setup"
    assert all(item["routing_evidence"] is False for item in startup)


def test_execution_readiness_refuses_unsafe_variant(tmp_path: Path) -> None:
    attributor = TransactionTraceAttributor(tmp_path / "trace", tmp_path / "brackets")
    unsafe = FirmwareTransaction.create(
        object_name="network.interface",
        method_name="reload",
        schema={},
        arguments={},
        setup_key="netifd",
    )
    called = False

    def call(_transaction: FirmwareTransaction) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        return subprocess.CompletedProcess([], 0, "", "")

    with pytest.raises(ValueError, match="unsafe readiness"):
        establish_transaction_readiness((unsafe,), call, attributor)
    assert called is False


def test_transaction_session_reaps_process_and_removes_owned_paths(tmp_path: Path) -> None:
    attributor = TransactionTraceAttributor(tmp_path / "trace", tmp_path / "brackets")
    owned = tmp_path / "runtime"
    owned.mkdir()
    process = subprocess.Popen(["sleep", "30"], start_new_session=True)
    session = FirmwareTransactionSession(tmp_path, attributor)
    session.own_process(process)
    session.own_path(owned)
    session.close()
    assert process.poll() is not None
    assert not owned.exists()


def test_transaction_session_cleans_up_when_body_fails(tmp_path: Path) -> None:
    attributor = TransactionTraceAttributor(tmp_path / "trace", tmp_path / "brackets")
    owned = tmp_path / "failed-runtime"
    owned.mkdir()
    process = subprocess.Popen(["sleep", "30"], start_new_session=True)
    with pytest.raises(RuntimeError, match="synthetic failure"):
        with FirmwareTransactionSession(tmp_path, attributor) as session:
            session.own_process(process)
            session.own_path(owned)
            raise RuntimeError("synthetic failure")
    assert process.poll() is not None
    assert not owned.exists()


@pytest.mark.skipif(
    not shutil.which("cc") or not shutil.which("qemu-x86_64"),
    reason="a C compiler and qemu-x86_64 are required",
)
def test_multi_address_qemu_instruction_tracer(tmp_path: Path) -> None:
    source = tmp_path / "two.c"
    binary = tmp_path / "two"
    source.write_text(
        """
        int main(void) {
            __asm__ volatile(".global exact_one\\nexact_one:");
            __asm__ volatile(".global exact_two\\nexact_two:");
            return 0;
        }
        """
    )
    subprocess.run(["cc", "-O0", "-no-pie", str(source), "-o", str(binary)], check=True)
    symbols = subprocess.check_output(["nm", str(binary)], text=True)
    addresses = [
        f"0x{int(line.split()[0], 16):X}"
        for line in symbols.splitlines()
        if line.endswith((" exact_one", " exact_two"))
    ]
    qemu = shutil.which("qemu-x86_64")
    tracer = compile_qemu_instruction_tracer(
        tmp_path / "plugin",
        addresses,
        qemu_user_bin=qemu,
        image_base=0x400000,
        binary_name=binary.name,
    )
    assert tracer["status"] == "configured"
    completed = subprocess.run(
        [qemu, *tracer["plugin_args"], "-L", "/", str(binary)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    hits = [json.loads(line) for line in Path(tracer["trace_path"]).read_text().splitlines()]
    assert {item["operation_address"].lower() for item in hits} == {item.lower() for item in addresses}
