"""Shared deterministic vulnerability discovery backends."""

from .base import DiscoveryBackend, DiscoveryContext, load_discovery_context
from .engine import (
    DiscoveryResult,
    discover_candidates,
    discovery_metrics,
    registered_backends,
    run_discovery,
    write_discovery_candidates,
    write_discovery_metrics,
)
from .semantic_seed import (
    DEFAULT_SEMANTIC_SEED_CLASSES,
    ExternalCommandSemanticSeedProvider,
    SemanticSeedProvider,
    build_semantic_feature_index,
    run_semantic_seed_stage,
    semantic_seed_candidates_from_artifacts,
)

__all__ = [
    "DEFAULT_SEMANTIC_SEED_CLASSES",
    "DiscoveryContext",
    "DiscoveryBackend",
    "DiscoveryResult",
    "ExternalCommandSemanticSeedProvider",
    "SemanticSeedProvider",
    "build_semantic_feature_index",
    "discover_candidates",
    "discovery_metrics",
    "registered_backends",
    "run_discovery",
    "load_discovery_context",
    "run_semantic_seed_stage",
    "semantic_seed_candidates_from_artifacts",
    "write_discovery_candidates",
    "write_discovery_metrics",
]
