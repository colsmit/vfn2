import argparse
import json
from pathlib import Path

from binary_agent.scale_study import run_scale_study


def main() -> None:
    parser = argparse.ArgumentParser(description="Plan clustered shared-setup proof work")
    parser.add_argument("candidate_states", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, default=None)
    parser.add_argument("--candidate-budget", type=int, default=64)
    parser.add_argument("--cache-dir", type=Path, default=Path(".ai/runs/execution-envelope-cache"))
    args = parser.parse_args()
    result = run_scale_study(
        args.candidate_states,
        args.output,
        rootfs_path=args.rootfs,
        candidate_budget=args.candidate_budget,
        cache_dir=args.cache_dir,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
