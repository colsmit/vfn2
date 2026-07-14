"""Deterministically reconstruct ranked firmware process launch recipes."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from binary_agent.pipeline import CandidateState


@dataclass(frozen=True)
class ProcessRecipe:
    recipe_id: str
    source: str
    confidence: float
    input_model: str
    argv: tuple[str, ...] = ()
    stdin: str = ""
    env: tuple[tuple[str, str], ...] = ()
    cwd: str = ""
    files: tuple[tuple[str, str], ...] = ()
    required_daemons: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["argv"] = list(self.argv)
        payload["env"] = dict(self.env)
        payload["files"] = [{"path": path, "content": content} for path, content in self.files]
        payload["required_daemons"] = list(self.required_daemons)
        payload["evidence_refs"] = list(self.evidence_refs)
        payload["limitations"] = list(self.limitations)
        return payload


@dataclass(frozen=True)
class RecipeSet:
    candidate_id: str
    binary_sha256: str
    rootfs_path: str
    recipes: tuple[ProcessRecipe, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "artifact_kind": "firmware_process_recipes",
            "candidate_id": self.candidate_id,
            "binary_sha256": self.binary_sha256,
            "rootfs_path": self.rootfs_path,
            "recipe_count": len(self.recipes),
            "recipes": [item.to_dict() for item in self.recipes],
            "authority": "ranked_launch_hypotheses_not_reach_or_vulnerability_observations",
        }


def reconstruct_process_recipes(
    state: CandidateState,
    binary_path: Path,
    *,
    rootfs_path: Path | None = None,
    limit: int = 8,
) -> RecipeSet:
    """Combine candidate facts, firmware files, and binary strings."""

    binary = Path(binary_path).expanduser().resolve()
    rootfs = Path(rootfs_path).expanduser().resolve() if rootfs_path else None
    process = state.type_facts.get("process_input")
    process = dict(process) if isinstance(process, Mapping) else {}
    recipes: list[ProcessRecipe] = []
    direct_argv = _strings(process.get("argv_values") or process.get("argv"))
    if direct_argv and direct_argv[0] in {"program", binary.name}:
        direct_argv = direct_argv[1:]
    stdin = str(process.get("stdin") or "")
    if not stdin and process.get("stdin_input_hex"):
        try:
            stdin = bytes.fromhex(str(process["stdin_input_hex"])).decode("latin-1")
        except ValueError:
            stdin = ""
    env_values = process.get("env_values") if isinstance(process.get("env_values"), Mapping) else {}
    input_model = str(process.get("input_model") or "argv")
    recipes.append(
        _recipe(
            state,
            "candidate-process-facts",
            0.95 if process else 0.35,
            input_model=input_model,
            argv=direct_argv,
            stdin=stdin,
            env=env_values,
            evidence=("candidate.type_facts.process_input",),
        )
    )
    file_name = str(process.get("file_name") or "")
    file_hex = str(process.get("file_input_hex") or "")
    if file_name and file_hex:
        try:
            file_content = bytes.fromhex(file_hex).decode("latin-1")
        except ValueError:
            file_content = ""
        recipes.append(
            _recipe(
                state,
                "candidate-file-seed",
                0.9,
                input_model="argv_file_stdin",
                argv=(file_name,),
                stdin=file_content,
                files=((file_name, file_content),),
                evidence=("candidate.type_facts.process_input.file_input_hex",),
            )
        )
    strings = _binary_strings(binary)
    dependencies = _dependencies(strings)
    component = str(state.target.get("component") or state.target.get("relative_path") or binary.name)
    if rootfs and rootfs.is_dir():
        recipes.extend(_init_script_recipes(state, binary.name, component, rootfs, dependencies))
        recipes.extend(_cgi_recipes(state, strings, rootfs))
    if dependencies:
        recipes.append(
            _recipe(
                state,
                "dependency-aware-direct",
                0.65,
                input_model=input_model,
                argv=direct_argv,
                stdin=stdin,
                env=env_values,
                required_daemons=dependencies,
                evidence=tuple(f"binary-string:{item}" for item in dependencies),
                limitations=("declared_dependencies_require_observed_replay_health",),
            )
        )
    unique: dict[tuple[Any, ...], ProcessRecipe] = {}
    for item in recipes:
        key = (item.input_model, item.argv, item.stdin, item.env, item.cwd, item.files, item.required_daemons)
        current = unique.get(key)
        if current is None or item.confidence > current.confidence:
            unique[key] = item
    ordered = tuple(
        sorted(unique.values(), key=lambda item: (-item.confidence, item.recipe_id))[: max(1, int(limit))]
    )
    return RecipeSet(
        candidate_id=state.candidate_id,
        binary_sha256=_sha256_file(binary),
        rootfs_path=str(rootfs) if rootfs else "",
        recipes=ordered,
    )


def write_process_recipes(recipes: RecipeSet, path: Path) -> Path:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(recipes.to_dict(), indent=2, sort_keys=True) + "\n")
    return Path(path)


def _recipe(
    state: CandidateState,
    source: str,
    confidence: float,
    *,
    input_model: str,
    argv: Sequence[str] = (),
    stdin: str = "",
    env: Mapping[str, Any] = {},
    cwd: str = "",
    files: Sequence[tuple[str, str]] = (),
    required_daemons: Sequence[str] = (),
    evidence: Sequence[str] = (),
    limitations: Sequence[str] = (),
) -> ProcessRecipe:
    fingerprint = json.dumps(
        [state.candidate_id, source, list(argv), stdin, sorted((str(k), str(v)) for k, v in env.items()), cwd],
        sort_keys=True,
    )
    return ProcessRecipe(
        recipe_id=hashlib.sha256(fingerprint.encode()).hexdigest()[:16],
        source=source,
        confidence=round(float(confidence), 4),
        input_model=input_model,
        argv=tuple(str(item) for item in argv),
        stdin=str(stdin),
        env=tuple(sorted((str(key), str(value)) for key, value in env.items())),
        cwd=str(cwd),
        files=tuple((str(path), str(content)) for path, content in files),
        required_daemons=tuple(sorted(set(str(item) for item in required_daemons))),
        evidence_refs=tuple(str(item) for item in evidence),
        limitations=tuple(str(item) for item in limitations),
    )


def _init_script_recipes(
    state: CandidateState,
    binary_name: str,
    component: str,
    rootfs: Path,
    dependencies: tuple[str, ...],
) -> list[ProcessRecipe]:
    rows: list[ProcessRecipe] = []
    roots = [rootfs / "etc/init.d", rootfs / "etc/rc.d", rootfs / "etc/config"]
    for directory in roots:
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.stat().st_size > 1024 * 1024:
                continue
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            if binary_name not in text and component not in text:
                continue
            for line in text.splitlines():
                stripped = line.strip()
                if binary_name not in stripped or stripped.startswith("#"):
                    continue
                argv = _shell_command_arguments(stripped, binary_name)
                rows.append(
                    _recipe(
                        state,
                        "firmware-init-script",
                        0.85,
                        input_model="argv",
                        argv=argv,
                        required_daemons=dependencies,
                        evidence=(str(path), stripped[:240]),
                        limitations=("shell_expansion_is_not_executed",),
                    )
                )
    return rows


def _cgi_recipes(state: CandidateState, strings: Sequence[str], rootfs: Path) -> list[ProcessRecipe]:
    routes = sorted({item for item in strings if item.startswith("/cgi-bin/") and len(item) < 200})[:4]
    rows = []
    for route in routes:
        rows.append(
            _recipe(
                state,
                "binary-cgi-route",
                0.7,
                input_model="stdin",
                stdin="value=replay\n",
                env={
                    "REQUEST_METHOD": "POST",
                    "REQUEST_URI": route,
                    "CONTENT_TYPE": "application/x-www-form-urlencoded",
                    "CONTENT_LENGTH": "13",
                },
                cwd="/www",
                evidence=(f"binary-string:{route}", str(rootfs / "www")),
            )
        )
    return rows


def _shell_command_arguments(line: str, binary_name: str) -> tuple[str, ...]:
    match = re.search(rf"(?:^|[\s/]){re.escape(binary_name)}(?:\s+([^;&|]+))?", line)
    if not match or not match.group(1):
        return ()
    return tuple(token for token in re.findall(r"[^\s]+", match.group(1)) if not token.startswith("$"))[:12]


def _dependencies(strings: Sequence[str]) -> tuple[str, ...]:
    joined = "\n".join(strings).lower()
    rows = []
    if any(token in joined for token in ("ubus_connect", "/var/run/ubus", "ubus.sock")):
        rows.append("ubusd")
    if "nvram_" in joined:
        rows.append("nvram")
    if "uci_" in joined or "/etc/config/" in joined:
        rows.append("uci-config")
    return tuple(rows)


def _binary_strings(binary: Path) -> tuple[str, ...]:
    try:
        completed = subprocess.run(
            ["strings", "-a", str(binary)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ()
    return tuple(line.strip() for line in completed.stdout.splitlines() if len(line.strip()) >= 4)


def _strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(str(item) for item in value)
    return ()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
