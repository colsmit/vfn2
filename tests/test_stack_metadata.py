import re

from binary_agent.analysis.stack import annotate_stack_locals, build_stack_objects, normalize_stack_regions
from tests.utils import make_function_node


STACK_REGIONS = [
    {"start_offset": -0x50, "end_offset": -0x30, "size_bytes": 0x20, "var_names": ["local_50", "local_48"], "data_types": ["undefined8"]},
    {"start_offset": -0x30, "end_offset": -0x20, "size_bytes": 0x10, "var_names": ["local_30"], "data_types": ["undefined8"]},
    {"start_offset": -0x20, "end_offset": -0x10, "size_bytes": 0x10, "var_names": ["local_20", "local_18"], "data_types": ["undefined8"]},
    {"start_offset": -0x10, "end_offset": -0x8, "size_bytes": 8, "var_names": [], "data_types": []},
]


def _build_node_with_text() -> tuple:
    text = """
void entry(void) {
  char *buf = (char *)&local_50;
  local_30 = local_30 + 1;
  local_20 = local_18 + 1;
}
""".strip()
    node = make_function_node(text=text, stack_regions=STACK_REGIONS)
    regions = normalize_stack_regions(node.record)
    return node, regions


def test_normalize_stack_regions_returns_all_entries():
    node = make_function_node(stack_regions=STACK_REGIONS)
    regions = normalize_stack_regions(node.record)

    assert len(regions) == 4
    assert regions[0]["label"] == "local_50..local_48"
    assert regions[-1]["label"] == "stack_region_4"
    assert regions[1]["offset_range"].startswith("[-0x30")
    assert regions[2]["size_hex"] == "0x10"


def test_annotate_stack_locals_marks_first_occurrence_only():
    node, regions = _build_node_with_text()
    annotated = annotate_stack_locals(node.text, regions)

    assert "local_50 /*" in annotated
    assert annotated.count("local_30 /*") == 1
    assert annotated.count("stack_region_4") == 0  # unlabeled region has no variable to annotate


def test_annotate_stack_locals_does_not_nest_annotations_from_region_labels():
    text = """
void sink(void) {
  undefined1 local_68 [16];
  undefined1 local_58 [16];
  undefined8 local_48;
}
""".strip()
    node = make_function_node(
        text=text,
        stack_regions=[
            {
                "start_offset": -0x68,
                "end_offset": -0x40,
                "size_bytes": 0x28,
                "var_names": ["local_68", "local_58", "local_48"],
                "data_types": ["undefined1[16]", "undefined8"],
            }
        ],
    )
    regions = normalize_stack_regions(node.record)

    annotated = annotate_stack_locals(node.text, regions)

    assert "local_68 /* local_68..local_48: stack[-0x68..-0x40], 40 bytes */ [16];" in annotated
    assert "local_58 /* local_68..local_48: stack[-0x68..-0x40], 40 bytes */ [16];" in annotated
    assert "local_48 /* local_68..local_48: stack[-0x68..-0x40], 40 bytes */;" in annotated
    assert "/* local_68..local_48 /*" not in annotated


def test_stack_annotations_mark_decompiler_excerpt():
    node, regions = _build_node_with_text()

    excerpt = annotate_stack_locals(node.text, regions)
    assert re.search(r"local_50\s/\*.*stack", excerpt)


def test_build_stack_objects_merges_contiguous_regions():
    node = make_function_node(
        stack_regions=[
            {
                "start_offset": -0x38,
                "end_offset": -0x28,
                "size_bytes": 0x10,
                "var_names": ["local_38"],
                "data_types": ["undefined1[16]"],
            },
            {
                "start_offset": -0x28,
                "end_offset": -0x18,
                "size_bytes": 0x10,
                "var_names": ["local_28"],
                "data_types": ["undefined1[16]"],
            },
            {
                "start_offset": -0x18,
                "end_offset": -0x10,
                "size_bytes": 0x8,
                "var_names": ["local_18"],
                "data_types": ["undefined8"],
            },
        ]
    )

    regions = normalize_stack_regions(node.record)
    objects = build_stack_objects(regions)

    assert len(objects) == 1
    assert objects[0]["label"] == "local_38..local_18"
    assert objects[0]["offset_range"] == "[-0x38..-0x10]"
    assert objects[0]["size_bytes"] == 40
