"""Common interfaces for deterministic discovery backends."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol

from binary_agent.analysis.program_index import ProgramIndex, build_program_index
from binary_agent.data.manifest import Manifest
from binary_agent.ingest.loader import FunctionNode, load_function_nodes
from binary_agent.pipeline import CandidateState


class DiscoveryBackend(Protocol):
    name: str

    def discover(
        self,
        context: "DiscoveryContext",
        index: ProgramIndex,
        enabled_types: frozenset[str],
    ) -> Iterable[CandidateState]:
        """Return deterministic candidates for selected terminal types."""


@dataclass(frozen=True)
class DiscoveryContext:
    export_dir: Path
    manifest: Manifest
    nodes: tuple[FunctionNode, ...]
    index: ProgramIndex
    intake_dir: Path | None = None
    intake_artifacts: Mapping[str, Any] = field(default_factory=dict)


def load_discovery_context(export_dir: Path, *, intake_dir: Path | None = None) -> DiscoveryContext:
    export_dir = Path(export_dir).expanduser().resolve()
    manifest, nodes = load_function_nodes(export_dir)
    artifacts: dict[str, Any] = {}
    if intake_dir is not None:
        intake_dir = Path(intake_dir).expanduser().resolve()
        for name in ("target", "binaries", "services", "routes", "configs", "analysis_manifest"):
            path = intake_dir / f"{name}.json"
            if path.exists():
                artifacts[name] = json.loads(path.read_text() or "{}")
    immutable_nodes = tuple(nodes)
    index = build_program_index(manifest, immutable_nodes)
    return DiscoveryContext(
        export_dir=export_dir,
        manifest=manifest,
        nodes=immutable_nodes,
        index=index,
        intake_dir=intake_dir,
        intake_artifacts=artifacts,
    )
