from binary_agent.proof_batching import plan_proof_batches
from binary_agent.scheduling import ProofAttempt


def test_proof_batches_charge_shared_setup_once() -> None:
    attempts = [
        ProofAttempt("a", "stack_overflow", "qemu_user", 1, 1, 10, (), setup_key="qemu:root", estimated_setup_seconds=1, estimated_marginal_seconds=9),
        ProofAttempt("b", "stack_overflow", "qemu_user", 2, 1, 10, (), setup_key="qemu:root", estimated_setup_seconds=1, estimated_marginal_seconds=9),
        ProofAttempt("c", "stack_overflow", "native_trace", 3, 1, 2, (), setup_key="native:c", estimated_setup_seconds=.15, estimated_marginal_seconds=1.85),
    ]
    batches = plan_proof_batches(attempts)
    shared = next(item for item in batches if item.setup_key == "qemu:root")
    assert shared.candidate_ids == ("a", "b")
    assert shared.projected_unbatched_seconds == 20
    assert shared.projected_batched_seconds == 19
    assert shared.projected_saved_seconds == 1
