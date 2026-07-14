import importlib.util
import sys
from pathlib import Path


_SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "build_romeo_ground_truth.py"
)
_SPEC = importlib.util.spec_from_file_location("build_romeo_ground_truth", _SCRIPT_PATH)
build_truth = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = build_truth
_SPEC.loader.exec_module(build_truth)


def _make_source_entry(tmp_path: Path, name: str, body: str) -> build_truth.SourceEntry:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    binary_key = build_truth.normalize_binary_key(path.stem)
    group_key = build_truth._group_key_from_name(binary_key).lower()
    ranges, errors = build_truth.parse_function_ranges(path)
    return build_truth.SourceEntry(
        manifest_rel=f"testcases/CWE121_Stack_Based_Buffer_Overflow/{name}",
        source_path=path,
        flaws=[],
        binary_key=binary_key,
        group_key=group_key,
        ranges=ranges,
        parse_errors=errors,
        source_lines=body.splitlines(),
    )


def test_build_ground_truth_infers_entry_functions_for_reachable_labels(
    tmp_path: Path,
) -> None:
    juliet_root = tmp_path / "juliet-test-suite-c"
    source_root = juliet_root / "testcases"
    source_dir = source_root / "CWE121_Stack_Based_Buffer_Overflow"
    source_dir.mkdir(parents=True)

    source_path = source_dir / "CWE121_Stack_Based_Buffer_Overflow__demo_01.c"
    source_path.write_text(
        "\n".join(
            [
                "void sink(void) {",
                "    char data[10];",
                "    fgets(data, sizeof(data), stdin);",
                "}",
                "",
                "void helper(void) {",
                "    sink();",
                "}",
                "",
                "void CWE121_Stack_Based_Buffer_Overflow__demo_01_bad(void) {",
                "    helper();",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    manifest_path = juliet_root / "manifest.xml"
    manifest_path.write_text(
        "\n".join(
            [
                "<testcases>",
                '  <file path="testcases/CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__demo_01.c">',
                '    <flaw line="3" name="CWE121_Stack_Based_Buffer_Overflow" />',
                "  </file>",
                "</testcases>",
                "",
            ]
        ),
        encoding="utf-8",
    )

    truth, metadata = build_truth.build_ground_truth(
        manifest_path=manifest_path,
        source_root=source_root,
        support_root=None,
        cwe_filter={121},
        attacker_controlled=True,
        input_apis={"fgets"},
        entry_functions_by_group=None,
    )

    entry = truth["cwe121_stack_based_buffer_overflow__demo_01"]
    assert entry.positives == ["sink"]
    assert entry.attacker_controlled["input_functions"] == ["sink"]
    assert entry.attacker_controlled["reachable_positives"] == ["sink"]
    assert entry.attacker_controlled["entry_functions"] == [
        "CWE121_Stack_Based_Buffer_Overflow__demo_01_bad"
    ]
    assert metadata["summary"]["attacker_controlled_reachable"] == 1


def test_infer_entry_functions_uses_source_context_for_cpp_bare_entries(
    tmp_path: Path,
) -> None:
    entry = _make_source_entry(
        tmp_path,
        "CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_33.cpp",
        "\n".join(
            [
                "namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_33 {",
                "void bad() {",
                "}",
                "static void goodG2B() {",
                "}",
                "static void goodB2G() {",
                "}",
                "void good() {",
                "}",
                "int main() {",
                "    return 0;",
                "}",
                "}",
                "",
            ]
        ),
    )

    assert build_truth._infer_entry_functions([entry]) == [
        "good",
        "goodB2G",
        "goodG2B",
        "bad",
    ]


def test_infer_entry_functions_uses_group_context_for_class_variants(
    tmp_path: Path,
) -> None:
    entry_a = _make_source_entry(
        tmp_path,
        "CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_81a.cpp",
        "\n".join(
            [
                "namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_81 {",
                "void bad() {",
                "}",
                "static void goodG2B() {",
                "}",
                "static void goodB2G() {",
                "}",
                "void good() {",
                "}",
                "}",
                "",
            ]
        ),
    )
    entry_bad = _make_source_entry(
        tmp_path,
        "CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_81_bad.cpp",
        "\n".join(
            [
                "namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_81 {",
                "void CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_81_bad::action(int data) const {",
                "    (void)data;",
                "}",
                "}",
                "",
            ]
        ),
    )

    assert build_truth._infer_entry_functions([entry_a, entry_bad]) == [
        "good",
        "goodB2G",
        "goodG2B",
        "bad",
    ]


def test_validate_attacker_controlled_truth_rejects_unresolved_defaults() -> None:
    metadata = {
        "summary": {
            "attacker_controlled_unknown": 2,
        }
    }

    try:
        build_truth.validate_attacker_controlled_truth(metadata)
    except ValueError as exc:
        assert "unresolved positives" in str(exc)
    else:
        raise AssertionError("expected unresolved attacker-controlled truth to fail")


def test_build_ground_truth_tracks_function_pointer_sink_reachability(
    tmp_path: Path,
) -> None:
    juliet_root = tmp_path / "juliet-test-suite-c"
    source_root = juliet_root / "testcases"
    source_dir = source_root / "CWE121_Stack_Based_Buffer_Overflow"
    source_dir.mkdir(parents=True)

    source_a = source_dir / "CWE121_Stack_Based_Buffer_Overflow__demo_65a.c"
    source_a.write_text(
        "\n".join(
            [
                "void CWE121_Stack_Based_Buffer_Overflow__demo_65b_badSink(int data);",
                "",
                "void CWE121_Stack_Based_Buffer_Overflow__demo_65_bad(void) {",
                "    int data = -1;",
                "    void (*funcPtr) (int) = CWE121_Stack_Based_Buffer_Overflow__demo_65b_badSink;",
                "    data = recv();",
                "    funcPtr(data);",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    source_b = source_dir / "CWE121_Stack_Based_Buffer_Overflow__demo_65b.c"
    source_b.write_text(
        "\n".join(
            [
                "void CWE121_Stack_Based_Buffer_Overflow__demo_65b_badSink(int data) {",
                "    int buffer[10] = {0};",
                "    buffer[data] = 1;",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    manifest_path = juliet_root / "manifest.xml"
    manifest_path.write_text(
        "\n".join(
            [
                "<testcases>",
                '  <file path="testcases/CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__demo_65a.c">',
                "  </file>",
                '  <file path="testcases/CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__demo_65b.c">',
                '    <flaw line="3" name="CWE121_Stack_Based_Buffer_Overflow" />',
                "  </file>",
                "</testcases>",
                "",
            ]
        ),
        encoding="utf-8",
    )

    truth, metadata = build_truth.build_ground_truth(
        manifest_path=manifest_path,
        source_root=source_root,
        support_root=None,
        cwe_filter={121},
        attacker_controlled=True,
        input_apis={"recv"},
        entry_functions_by_group={
            "cwe121_stack_based_buffer_overflow__demo_65": [
                "CWE121_Stack_Based_Buffer_Overflow__demo_65_bad"
            ]
        },
    )

    entry = truth["cwe121_stack_based_buffer_overflow__demo_65b"]
    assert entry.positives == ["CWE121_Stack_Based_Buffer_Overflow__demo_65b_badSink"]
    assert entry.attacker_controlled["input_functions"] == [
        "CWE121_Stack_Based_Buffer_Overflow__demo_65_bad"
    ]
    assert (
        entry.attacker_controlled["tainted_functions"]
        == [
            "CWE121_Stack_Based_Buffer_Overflow__demo_65_bad",
            "CWE121_Stack_Based_Buffer_Overflow__demo_65b_badSink",
        ]
    )
    assert entry.attacker_controlled["positives"] == [
        "CWE121_Stack_Based_Buffer_Overflow__demo_65b_badSink"
    ]
    assert entry.attacker_controlled["unknown_positives"] == []
    assert entry.attacker_controlled["reachable_positives"] == [
        "CWE121_Stack_Based_Buffer_Overflow__demo_65b_badSink"
    ]
    assert metadata["summary"]["attacker_controlled_unknown"] == 0
    assert metadata["summary"]["attacker_controlled_reachable"] == 1


def test_build_ground_truth_marks_destructor_sinks_tainted_when_constructor_reads_input(
    tmp_path: Path,
) -> None:
    juliet_root = tmp_path / "juliet-test-suite-c"
    source_root = juliet_root / "testcases"
    source_dir = source_root / "CWE121_Stack_Based_Buffer_Overflow"
    source_dir.mkdir(parents=True)

    source_path = source_dir / "CWE121_Stack_Based_Buffer_Overflow__demo_83.cpp"
    source_path.write_text(
        "\n".join(
            [
                "class CWE121_Stack_Based_Buffer_Overflow__demo_83_bad {",
                "public:",
                "    CWE121_Stack_Based_Buffer_Overflow__demo_83_bad(int dataCopy) {",
                "        data = dataCopy;",
                "        data = recv();",
                "    }",
                "    ~CWE121_Stack_Based_Buffer_Overflow__demo_83_bad() {",
                "        int buffer[10] = {0};",
                "        buffer[data] = 1;",
                "    }",
                "private:",
                "    int data;",
                "};",
                "",
                "void CWE121_Stack_Based_Buffer_Overflow__demo_83_bad() {",
                "    CWE121_Stack_Based_Buffer_Overflow__demo_83_bad badObject(0);",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    manifest_path = juliet_root / "manifest.xml"
    manifest_path.write_text(
        "\n".join(
            [
                "<testcases>",
                '  <file path="testcases/CWE121_Stack_Based_Buffer_Overflow/CWE121_Stack_Based_Buffer_Overflow__demo_83.cpp">',
                '    <flaw line="8" name="CWE121_Stack_Based_Buffer_Overflow" />',
                "  </file>",
                "</testcases>",
                "",
            ]
        ),
        encoding="utf-8",
    )

    truth, metadata = build_truth.build_ground_truth(
        manifest_path=manifest_path,
        source_root=source_root,
        support_root=None,
        cwe_filter={121},
        attacker_controlled=True,
        input_apis={"recv"},
        entry_functions_by_group={
            "cwe121_stack_based_buffer_overflow__demo_83": [
                "CWE121_Stack_Based_Buffer_Overflow__demo_83_bad"
            ]
        },
    )

    entry = truth["cwe121_stack_based_buffer_overflow__demo_83"]
    assert entry.attacker_controlled["input_functions"] == [
        "CWE121_Stack_Based_Buffer_Overflow__demo_83_bad",
        "CWE121_Stack_Based_Buffer_Overflow__demo_83_bad",
    ] or entry.attacker_controlled["input_functions"] == [
        "CWE121_Stack_Based_Buffer_Overflow__demo_83_bad"
    ]
    assert entry.attacker_controlled["positives"] == [
        "~CWE121_Stack_Based_Buffer_Overflow__demo_83_bad"
    ]
    assert entry.attacker_controlled["unknown_positives"] == []
    assert entry.attacker_controlled["reachable_positives"] == [
        "~CWE121_Stack_Based_Buffer_Overflow__demo_83_bad"
    ]
    assert "~CWE121_Stack_Based_Buffer_Overflow__demo_83_bad" in entry.attacker_controlled["tainted_functions"]
    assert metadata["summary"]["attacker_controlled_unknown"] == 0
