from binary_agent.analysis.fact_enrichment import parse_affine_expr, prove_relational_allocation_write


def test_affine_parser_supports_multiple_symbols_and_rejects_nonlinear_terms() -> None:
    expression = parse_affine_expr("2 * left + right - left + 3")
    assert expression is not None
    assert expression.to_dict()["coefficients"] == {"left": 1, "right": 1}
    assert expression.constant == 3
    assert parse_affine_expr("left * right") is None


def test_relational_proof_snapshots_safe_allocation_and_rejects_undersizing() -> None:
    safe = """size_t a = strlen(left);
size_t b = strlen(right);
char *out = malloc(a + b + 2);
strcpy(out + a + 1, right);"""
    candidate = {"line_number": 4, "sink": "strcpy", "target_buffer": "out", "write_relation": "unbounded"}
    proof = prove_relational_allocation_write(candidate, source_text=safe)
    assert proof["status"] == "proven_safe"
    assert proof["all_paths_proven"] is True

    unsafe = safe.replace("a + b + 2", "a + b")
    proof = prove_relational_allocation_write(candidate, source_text=unsafe)
    assert proof["status"] == "unknown"
    assert proof["all_paths_proven"] is False


def test_relational_proof_uses_allocation_execution_snapshot() -> None:
    source = """size_t n = strlen(input);
char *out = malloc(n + 1);
n += 8;
strcpy(out, input);"""
    proof = prove_relational_allocation_write(
        {"line_number": 4, "sink": "strcpy", "target_buffer": "out"},
        source_text=source,
    )
    assert proof["status"] == "proven_safe"
    assert proof["allocation"]["expression"] == "strlen(input) + 1"


def test_relational_proof_requires_every_branch_to_be_safe() -> None:
    source = """char *out;
size_t n = strlen(input);
if (flag) {
  out = malloc(n + 1);
} else {
  out = malloc(n);
}
strcpy(out, input);"""
    proof = prove_relational_allocation_write(
        {"line_number": 8, "sink": "strcpy", "target_buffer": "out"},
        source_text=source,
    )
    assert proof["status"] == "unknown"
    assert proof["all_paths_proven"] is False


def test_relational_proof_discards_only_a_terminating_error_path() -> None:
    source = """size_t n = strlen(input);
char *out = malloc(n + 1);
if (out == 0) {
  goto done;
}
strcpy(out, input);
done:
return;"""
    proof = prove_relational_allocation_write(
        {"line_number": 6, "sink": "strcpy", "target_buffer": "out"},
        source_text=source,
    )
    assert proof["status"] == "proven_safe"


def test_relational_proof_rejects_negative_and_unsupported_loop_relations() -> None:
    negative = """size_t n = strlen(input);
char *out = malloc(n + 1);
strcpy(out - 1, input);"""
    proof = prove_relational_allocation_write(
        {"line_number": 3, "sink": "strcpy", "target_buffer": "out"},
        source_text=negative,
    )
    assert proof["status"] == "unknown"

    unsupported_loop = """size_t n = strlen(input);
char *out = malloc(n + 1);
while (again) {
  n -= 1;
}
strcpy(out, input);"""
    proof = prove_relational_allocation_write(
        {"line_number": 6, "sink": "strcpy", "target_buffer": "out"},
        source_text=unsupported_loop,
    )
    assert proof["status"] == "unknown"


def test_relational_proof_fails_closed_for_else_if_and_ambiguous_same_line_write() -> None:
    else_if = """size_t n = strlen(input);
char *out = malloc(n + 1);
if (flag) {
  observe();
} else if (other) {
  observe();
}
strcpy(out, input);"""
    proof = prove_relational_allocation_write(
        {"line_number": 7, "sink": "strcpy", "target_buffer": "out"},
        source_text=else_if,
    )
    assert proof["status"] == "unknown"

    same_line = """size_t n = strlen(input);
char *out = malloc(n + 1);
strcpy(out, input); strcpy(out, input);"""
    proof = prove_relational_allocation_write(
        {"line_number": 3, "sink": "strcpy", "target_buffer": "out"},
        source_text=same_line,
    )
    assert proof["status"] == "unknown"
    assert "exactly one strcpy" in proof["reason"]


def test_relational_proof_models_a_nonnegative_loop_accumulator() -> None:
    source = """size_t total = 0;
char *out = 0;
do {
  size_t left_len = strlen(left);
  size_t right_len = strlen(right);
  if (total == 0) {
    total = left_len + right_len;
    out = malloc(total + 3);
  } else {
    total = total + left_len + right_len;
    out = realloc(out, total + 3);
  }
  total += 2;
  if (out == 0) {
    goto done;
  }
  strcpy(out + ((total - right_len) - left_len) - 2, left);
} while (again);
done:
return;"""
    proof = prove_relational_allocation_write(
        {"line_number": 17, "sink": "strcpy", "target_buffer": "out"},
        source_text=source,
    )
    assert proof["status"] == "proven_safe"
    assert any("loop_accumulator(total)" in path["allocation"]["expression"] for path in proof["paths"])
