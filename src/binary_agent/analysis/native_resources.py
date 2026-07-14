"""Generation-aware runtime ledger for native resource lifetime proof."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class RuntimeResource:
    kind: str
    identity: int
    generation: int
    family: str
    live: bool


class RuntimeResourceLedger:
    """Track raw handles without confusing a reused value for an old resource."""

    def __init__(self) -> None:
        self._resources: dict[tuple[str, int], RuntimeResource] = {}
        self._generations: dict[tuple[str, int], int] = {}
        self.events: list[dict[str, Any]] = []

    def acquire(self, kind: str, identity: int, family: str) -> RuntimeResource | None:
        if not _valid_identity(kind, identity):
            return None
        key = (kind, int(identity))
        generation = self._generations.get(key, 0) + 1
        self._generations[key] = generation
        resource = RuntimeResource(kind, int(identity), generation, family, True)
        self._resources[key] = resource
        self._append("acquire", resource, live_before=False, family=family)
        return resource

    def use(self, identity: int, kinds: Iterable[str]) -> RuntimeResource | None:
        resource = self.lookup(identity, kinds)
        if resource is not None:
            self._append("use", resource, live_before=resource.live, family=resource.family)
        return resource

    def release(
        self,
        identity: int,
        kinds: Iterable[str],
        family: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> RuntimeResource | None:
        resource = self.lookup(identity, kinds)
        if resource is None:
            return None
        self._append(
            "release",
            resource,
            live_before=resource.live,
            family=family,
            details=details,
        )
        self._resources[(resource.kind, resource.identity)] = RuntimeResource(
            resource.kind,
            resource.identity,
            resource.generation,
            resource.family,
            False,
        )
        return resource

    def duplicate_releases(self, *, kinds: Iterable[str] = ()) -> list[dict[str, Any]]:
        """Return releases of an already-dead identity generation."""

        requested = set(str(item) for item in kinds)
        return [
            dict(event)
            for event in self.events
            if event.get("action") == "release"
            and event.get("live_before") is False
            and (not requested or str(event.get("resource_kind") or "") in requested)
        ]

    def lookup(self, identity: int, kinds: Iterable[str] = ()) -> RuntimeResource | None:
        requested = tuple(kinds)
        rows = [
            resource
            for (kind, value), resource in self._resources.items()
            if value == int(identity) and (not requested or kind in requested)
        ]
        return max(rows, key=lambda item: item.generation, default=None)

    def violation(
        self,
        vulnerability_type: str,
        identity: int,
        *,
        kinds: Iterable[str] = (),
        release_family: str = "",
    ) -> dict[str, Any]:
        resource = self.lookup(identity, kinds)
        if resource is None:
            return {"violation": False, "same_resource": False, "events": []}
        relevant = [
            event
            for event in self.events
            if event["resource_kind"] == resource.kind
            and event["identity"] == resource.identity
            and event["generation"] == resource.generation
        ]
        violation = False
        if vulnerability_type in {"double_free", "use_after_free", "double_close", "use_after_close"}:
            violation = not resource.live and any(event["action"] == "release" for event in relevant)
        elif vulnerability_type == "mismatched_deallocator":
            violation = bool(resource.live and release_family and resource.family != release_family)
        elif vulnerability_type == "memory_leak":
            violation = bool(
                resource.live
                and any(event["action"] == "scope_exit" for event in relevant)
            )
        payload = {
            "vulnerability": vulnerability_type,
            "violation": violation,
            "same_resource": True,
            "resource_kind": resource.kind,
            "resource_identity": resource.identity,
            "resource_generation": resource.generation,
            "allocator_family": resource.family,
            "deallocator_family": release_family,
            "events": relevant,
        }
        return payload

    def scope_exit(self, label: str) -> list[RuntimeResource]:
        """Record which exact generations remain live at a function exit."""

        live = [resource for resource in self._resources.values() if resource.live]
        for resource in live:
            self._append(
                "scope_exit",
                resource,
                live_before=True,
                family=resource.family,
                details={"scope_exit": str(label)},
            )
        return live

    def _append(
        self,
        action: str,
        resource: RuntimeResource,
        *,
        live_before: bool,
        family: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.events.append(
            {
                "sequence": len(self.events) + 1,
                "action": action,
                "resource_kind": resource.kind,
                "identity": resource.identity,
                "generation": resource.generation,
                "family": family,
                "live_before": live_before,
                **dict(details or {}),
            }
        )


def _valid_identity(kind: str, identity: int) -> bool:
    return int(identity) > 0 if kind in {"heap", "stream", "directory"} else int(identity) >= 0
