"""Validated declarative proof obligations and backend route hints."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.pipeline import CandidateState
from binary_agent.taxonomy import VULNERABILITY_SPECS


DEFAULT_PROOF_SPECS_PATH = Path(__file__).with_name("proof_specs.json")
PROOF_SPEC_VERSION = 3
FORBIDDEN_OBSERVATION_KEYS = frozenset(
    {"status", "observed", "proven", "bug_observed", "exact_operation_reached", "sink_reached"}
)


@dataclass(frozen=True)
class ProofRouteSpec:
    name: str
    execution_family: str
    estimated_seconds: float


@dataclass(frozen=True)
class ProofSpec:
    name: str
    policy: str
    scope: str
    effect_kind: str
    routes: tuple[str, ...]
    requirements: tuple[str, ...]


@dataclass(frozen=True)
class ProofSpecSet:
    version: int
    routes: tuple[ProofRouteSpec, ...]
    classes: tuple[ProofSpec, ...]
    path: str = ""

    def get(self, name: str) -> ProofSpec:
        try:
            return next(item for item in self.classes if item.name == name)
        except StopIteration as exc:
            raise ValueError(f"proof specification is missing {name!r}") from exc

    def route(self, name: str) -> ProofRouteSpec:
        try:
            return next(item for item in self.routes if item.name == name)
        except StopIteration as exc:
            raise ValueError(f"proof route is missing {name!r}") from exc


@dataclass(frozen=True)
class CompiledProofPlan:
    candidate_id: str
    vulnerability_type: str
    policy: str
    scope: str
    effect_kind: str
    routes: tuple[ProofRouteSpec, ...]
    requirements: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "artifact_kind": "compiled_proof_plan",
            "candidate_id": self.candidate_id,
            "vulnerability_type": self.vulnerability_type,
            "policy": self.policy,
            "scope": self.scope,
            "effect_kind": self.effect_kind,
            "routes": [asdict(item) for item in self.routes],
            "requirements": list(self.requirements),
            "authority": "requirements_only",
        }


def load_proof_specs(path: Path | str | None = None) -> ProofSpecSet:
    spec_path = Path(path) if path is not None else DEFAULT_PROOF_SPECS_PATH
    payload = json.loads(spec_path.read_text())
    if not isinstance(payload, Mapping):
        raise ValueError("proof specification must contain an object")
    _reject_observation_values(payload)
    version = int(payload.get("version") or 0)
    if version != PROOF_SPEC_VERSION:
        raise ValueError(f"proof specification version {version} is unsupported")
    raw_routes = payload.get("routes")
    raw_classes = payload.get("classes")
    if not isinstance(raw_routes, Mapping) or not isinstance(raw_classes, Mapping):
        raise ValueError("proof specification requires routes and classes objects")
    routes = tuple(
        ProofRouteSpec(
            name=str(name),
            execution_family=str(raw.get("execution_family") or ""),
            estimated_seconds=float(raw.get("estimated_seconds") or 0.0),
        )
        for name, raw in raw_routes.items()
        if isinstance(raw, Mapping)
    )
    if not routes or any(not item.execution_family or item.estimated_seconds <= 0 for item in routes):
        raise ValueError("every proof route requires a family and positive estimated time")
    route_names = {item.name for item in routes}
    taxonomy_names = set(VULNERABILITY_SPECS)
    if set(raw_classes) != taxonomy_names:
        missing = sorted(taxonomy_names - set(raw_classes))
        extra = sorted(set(raw_classes) - taxonomy_names)
        raise ValueError(f"proof class mismatch: missing={missing}, extra={extra}")
    classes: list[ProofSpec] = []
    for name, raw in raw_classes.items():
        if not isinstance(raw, Mapping):
            raise ValueError(f"proof class {name!r} must be an object")
        unknown = set(raw) - {"policy", "scope", "effect_kind", "routes", "requirements"}
        if unknown:
            raise ValueError(f"proof class {name!r} has unknown fields: {sorted(unknown)}")
        taxonomy = VULNERABILITY_SPECS[name]
        policy = str(raw.get("policy") or "")
        effect_kind = str(raw.get("effect_kind") or "")
        route_values = _strings(raw.get("routes"))
        requirements = _strings(raw.get("requirements"))
        if policy != taxonomy.proof_policy:
            raise ValueError(f"proof class {name!r} policy does not match taxonomy")
        if effect_kind != taxonomy.effect_kind:
            raise ValueError(f"proof class {name!r} effect kind does not match taxonomy")
        if not route_values or set(route_values) - route_names:
            raise ValueError(f"proof class {name!r} contains an unknown or empty route")
        if not requirements:
            raise ValueError(f"proof class {name!r} requires evidence requirements")
        classes.append(
            ProofSpec(
                name=name,
                policy=policy,
                scope=str(raw.get("scope") or ""),
                effect_kind=effect_kind,
                routes=tuple(route_values),
                requirements=tuple(requirements),
            )
        )
    return ProofSpecSet(version, tuple(routes), tuple(classes), str(spec_path))


def compile_proof_plan(
    state: CandidateState,
    specs: ProofSpecSet | None = None,
) -> CompiledProofPlan:
    selected = specs or load_proof_specs()
    spec = selected.get(state.vulnerability_type)
    if state.backend != spec.policy:
        raise ValueError(
            f"candidate backend {state.backend!r} does not match proof policy {spec.policy!r}"
        )
    return CompiledProofPlan(
        candidate_id=state.candidate_id,
        vulnerability_type=state.vulnerability_type,
        policy=spec.policy,
        scope=spec.scope,
        effect_kind=spec.effect_kind,
        routes=tuple(selected.route(name) for name in spec.routes),
        requirements=spec.requirements,
    )


def attach_compiled_proof_plan(
    state: CandidateState,
    specs: ProofSpecSet | None = None,
) -> CandidateState:
    """Attach requirements without modifying status, blockers, or identity."""

    plan = compile_proof_plan(state, specs)
    return state.with_updates(
        metadata={**dict(state.metadata), "compiled_proof_plan": plan.to_dict()}
    )


def _reject_observation_values(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key)
            if name in FORBIDDEN_OBSERVATION_KEYS:
                raise ValueError(
                    "proof specifications describe requirements, not observations: "
                    + ".".join((*path, name))
                )
            _reject_observation_values(item, (*path, name))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _reject_observation_values(item, (*path, str(index)))


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError("proof routes and requirements must be non-empty string arrays")
    return list(value)
