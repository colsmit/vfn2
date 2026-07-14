#!/usr/bin/env python3
"""Fetch and build the source-backed known-overflow corpus binaries."""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import tarfile
import urllib.request
from pathlib import Path
from typing import Any


PACKAGES: dict[str, dict[str, Any]] = {
    "gzip-1.2.4": {
        "archive": "gzip-1.2.4.tar.gz",
        "url": "https://ftp.gnu.org/gnu/gzip/gzip-1.2.4.tar.gz",
        "builder": "gzip",
    },
    "tiff-3.9.4": {
        "archive": "tiff-3.9.4.tar.gz",
        "url": "https://download.osgeo.org/libtiff/old/tiff-3.9.4.tar.gz",
        "builder": "libtiff",
    },
    "ncompress-4.2.4": {
        "archive": "ncompress-4.2.4.tar.gz",
        "url": "https://downloads.sourceforge.net/project/ncompress/old%20releases/ncompress-4.2.4.tar.gz",
        "builder": "ncompress",
    },
    "sharutils-4.2.1": {
        "archive": "sharutils-4.2.1.tar.gz",
        "url": "https://ftp.gnu.org/gnu/sharutils/sharutils-4.2.1.tar.gz",
        "builder": "sharutils",
    },
    "sharutils-4.15.2": {
        "archive": "sharutils-4.15.2.tar.gz",
        "url": "https://ftp.gnu.org/gnu/sharutils/sharutils-4.15.2.tar.gz",
        "builder": "sharutils_4152",
    },
    "tar-1.34": {
        "archive": "tar-1.34.tar.gz",
        "url": "https://ftp.gnu.org/gnu/tar/tar-1.34.tar.gz",
        "builder": "tar",
    },
    "unarj-2.63a": {
        "archive": "unarj-2.63a.tar.gz",
        "url": "https://www.ibiblio.org/pub/Linux/utils/compress/unarj-2.63a.tar.gz",
        "builder": "unarj",
    },
    "unzip-5.50": {
        "archive": "unzip550.tar.gz",
        "url": "https://ifarchive.org/if-archive/download-tools/unzip550.tar.gz",
        "builder": "unzip",
    },
    "goahead-2.1": {
        "archive": "goahead-2.1.tar.gz",
        "url": "https://raw.githubusercontent.com/trenta3/goahead-versions/master/00828427Webs21.tar.gz",
        "builder": "goahead21",
        "flat_archive": True,
    },
}

COMMON_CFLAGS = "-O0 -g0 -fno-stack-protector -U_FORTIFY_SOURCE -no-pie -fcommon -w"
COMMON_LDFLAGS = "-no-pie"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path("tmp/known_overflow_sources"))
    parser.add_argument("--case", choices=sorted(PACKAGES), action="append", dest="cases")
    parser.add_argument("--cc", default=os.environ.get("CC", "gcc"))
    parser.add_argument("--jobs", type=int, default=max(1, min(os.cpu_count() or 1, 8)))
    parser.add_argument("--force-fetch", action="store_true")
    parser.add_argument("--force-extract", action="store_true")
    return parser.parse_args()


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None, check: bool = True) -> None:
    print(f"[+] {cwd}: {' '.join(command)}")
    completed = subprocess.run(command, cwd=cwd, env=env, check=False)
    if check and completed.returncode != 0:
        raise SystemExit(completed.returncode)


def download(url: str, archive_path: Path, *, force: bool) -> None:
    if archive_path.exists() and not force:
        return
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] Downloading {url} -> {archive_path}")
    with urllib.request.urlopen(url, timeout=60) as response:
        archive_path.write_bytes(response.read())


def safe_extract(archive_path: Path, source_root: Path, package_dir: Path, *, force: bool, flat: bool = False) -> None:
    if package_dir.exists() and not force:
        return
    if package_dir.exists():
        shutil.rmtree(package_dir)
    if flat:
        package_dir.mkdir(parents=True, exist_ok=True)
    root = source_root.resolve()
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            destination_root = package_dir if flat else source_root
            destination = (destination_root / member.name).resolve()
            if root != destination and root not in destination.parents:
                raise ValueError(f"archive member escapes source root: {member.name}")
        archive.extractall(package_dir if flat else source_root)
    if not package_dir.exists():
        raise FileNotFoundError(f"expected extracted directory not found: {package_dir}")


def strip_binary(src: Path, dst: Path) -> None:
    strip = shutil.which("strip")
    if not strip:
        raise FileNotFoundError("strip is required to create corpus *_stripped binaries")
    run([strip, "-o", str(dst), str(src)], cwd=src.parent)


def build_gzip(source_dir: Path, *, cc: str, jobs: int) -> list[Path]:
    env = os.environ.copy()
    env.update({"CC": cc, "CFLAGS": COMMON_CFLAGS, "LDFLAGS": COMMON_LDFLAGS})
    run(["./configure"], cwd=source_dir, env=env)
    run(["make", "clean"], cwd=source_dir, env=env, check=False)
    run(["make", f"-j{jobs}"], cwd=source_dir, env=env)
    outputs = []
    for name in ("gzip", "gunzip", "zcat"):
        binary = source_dir / name
        stripped = source_dir / f"{name}_stripped"
        strip_binary(binary, stripped)
        outputs.append(stripped)
    return outputs


def build_libtiff(source_dir: Path, *, cc: str, jobs: int) -> list[Path]:
    env = os.environ.copy()
    env.update({"CC": cc, "CFLAGS": COMMON_CFLAGS, "LDFLAGS": COMMON_LDFLAGS})
    run(
        [
            "./configure",
            "--disable-shared",
            "--disable-cxx",
            "--disable-jpeg",
            "--disable-zlib",
        ],
        cwd=source_dir,
        env=env,
    )
    run(["make", "clean"], cwd=source_dir, env=env, check=False)
    run(["make", f"-j{jobs}"], cwd=source_dir, env=env)
    stripped = source_dir / "tools" / "tiff2pdf_stripped"
    strip_binary(source_dir / "tools" / "tiff2pdf", stripped)
    return [stripped]


def build_sharutils(source_dir: Path, *, cc: str, jobs: int) -> list[Path]:
    env = os.environ.copy()
    env.update(
        {
            "CC": cc,
            "CFLAGS": COMMON_CFLAGS,
            "LDFLAGS": COMMON_LDFLAGS,
            "FORCE_UNSAFE_CONFIGURE": "1",
        }
    )
    run(["./configure", "--disable-nls"], cwd=source_dir, env=env)
    run(["make", "clean"], cwd=source_dir, env=env, check=False)
    run(["make", f"-j{jobs}"], cwd=source_dir, env=env)
    outputs = []
    for name in ("shar", "unshar", "uudecode"):
        binary = source_dir / "src" / name
        stripped = source_dir / "src" / f"{name}_stripped"
        strip_binary(binary, stripped)
        outputs.append(stripped)
    return outputs


def build_sharutils_4152(source_dir: Path, *, cc: str, jobs: int) -> list[Path]:
    env = os.environ.copy()
    env.update(
        {
            "CC": cc,
            "CFLAGS": f"{COMMON_CFLAGS} -Drpl_fseeko=fseeko",
            "LDFLAGS": COMMON_LDFLAGS,
            "FORCE_UNSAFE_CONFIGURE": "1",
        }
    )
    run(["./configure", "--disable-nls"], cwd=source_dir, env=env)
    run(["make", "clean"], cwd=source_dir, env=env, check=False)
    makefile = source_dir / "lib" / "Makefile"
    makefile.write_text(
        makefile.read_text(encoding="utf-8").replace(" fseeko.o", "").replace(" fseeko.lo", ""),
        encoding="utf-8",
    )
    run(["make", f"-j{jobs}"], cwd=source_dir, env=env)
    outputs = []
    for name in ("unshar",):
        binary = source_dir / "src" / name
        stripped = source_dir / "src" / f"{name}_stripped"
        strip_binary(binary, stripped)
        outputs.append(stripped)
    return outputs


def build_ncompress(source_dir: Path, *, cc: str, jobs: int) -> list[Path]:
    for name in ("compress", "compress_stripped"):
        try:
            (source_dir / name).unlink()
        except FileNotFoundError:
            pass
    run(
        [
            cc,
            *shlex.split(COMMON_CFLAGS),
            "-DNOFUNCDEF=1",
            "-DDIRENT=1",
            "-DUSERMEM=800000",
            "-DREGISTERS=3",
            '-DCOMPILE_DATE="source-build"',
            "compress42.c",
            "-o",
            "compress",
            *shlex.split(COMMON_LDFLAGS),
        ],
        cwd=source_dir,
    )
    stripped = source_dir / "compress_stripped"
    strip_binary(source_dir / "compress", stripped)
    return [stripped]


def build_tar(source_dir: Path, *, cc: str, jobs: int) -> list[Path]:
    env = os.environ.copy()
    env.update(
        {
            "CC": cc,
            "CFLAGS": COMMON_CFLAGS,
            "LDFLAGS": COMMON_LDFLAGS,
            "FORCE_UNSAFE_CONFIGURE": "1",
        }
    )
    run(["./configure", "--disable-nls"], cwd=source_dir, env=env)
    run(["make", "clean"], cwd=source_dir, env=env, check=False)
    run(["make", f"-j{jobs}"], cwd=source_dir, env=env)
    stripped = source_dir / "src" / "tar_stripped"
    strip_binary(source_dir / "src" / "tar", stripped)
    return [stripped]


def build_unarj(source_dir: Path, *, cc: str, jobs: int) -> list[Path]:
    run(["make", "clean"], cwd=source_dir, check=False)
    run(["make", f"-j{jobs}", "unarj", f"CC={cc}", f"CFLAGS={COMMON_CFLAGS} -DUNIX"], cwd=source_dir)
    stripped = source_dir / "unarj_stripped"
    strip_binary(source_dir / "unarj", stripped)
    return [stripped]


def build_unzip(source_dir: Path, *, cc: str, jobs: int) -> list[Path]:
    run(["make", "-f", "unix/Makefile", "clean"], cwd=source_dir, check=False)
    run(
        [
            "make",
            f"-j{jobs}",
            "-f",
            "unix/Makefile",
            "unzips",
            f"CC={cc}",
            f"LD={cc}",
            f"CF={COMMON_CFLAGS} -I.",
            f"LF={COMMON_LDFLAGS} -o unzip",
            f"SL={COMMON_LDFLAGS} -o unzipsfx",
            f"FL={COMMON_LDFLAGS} -o funzip",
            "LF2=",
            "SL2=",
            "FL2=",
        ],
        cwd=source_dir,
    )
    outputs = []
    for name in ("unzip", "funzip", "unzipsfx"):
        binary = source_dir / name
        stripped = source_dir / f"{name}_stripped"
        strip_binary(binary, stripped)
        outputs.append(stripped)
    return outputs


def build_goahead21(source_dir: Path, *, cc: str, jobs: int) -> list[Path]:
    misc = source_dir / "misc.c"
    misc.write_text(misc.read_text(encoding="latin-1").replace("strnlen", "websStrnlen"), encoding="latin-1")
    main = source_dir / "LINUX" / "main.c"
    main.write_text(main.read_text(encoding="latin-1").replace("static int\t\t\tport = 80;", "static int\t\t\tport = 18080;"), encoding="latin-1")
    common = f'-DWEBS -DUEMF -DOS="LINUX" -DLINUX -D_STRUCT_TIMEVAL=1 -DUSER_MANAGEMENT_SUPPORT -DDIGEST_ACCESS_SUPPORT {COMMON_CFLAGS}'
    run(["make", "clean"], cwd=source_dir / "LINUX", check=False)
    run(
        [
            "make",
            f"-j{jobs}",
            f"CC={cc}",
            "AR=ar",
            "ARFLAGS=rc",
            f"CFLAGS={common}",
            "DEBUG=",
            f"LDFLAGS={COMMON_LDFLAGS}",
        ],
        cwd=source_dir / "LINUX",
    )
    stripped = source_dir / "LINUX" / "webs_stripped"
    strip_binary(source_dir / "LINUX" / "webs", stripped)
    return [stripped]


def build_package(name: str, package: dict[str, Any], args: argparse.Namespace) -> list[Path]:
    source_root = args.source_root if args.source_root.is_absolute() else Path.cwd() / args.source_root
    archive_path = source_root / str(package["archive"])
    source_dir = source_root / name
    download(str(package["url"]), archive_path, force=args.force_fetch)
    safe_extract(archive_path, source_root, source_dir, force=args.force_extract, flat=bool(package.get("flat_archive")))
    builder = str(package["builder"])
    if builder == "gzip":
        return build_gzip(source_dir, cc=args.cc, jobs=args.jobs)
    if builder == "libtiff":
        return build_libtiff(source_dir, cc=args.cc, jobs=args.jobs)
    if builder == "sharutils":
        return build_sharutils(source_dir, cc=args.cc, jobs=args.jobs)
    if builder == "sharutils_4152":
        return build_sharutils_4152(source_dir, cc=args.cc, jobs=args.jobs)
    if builder == "ncompress":
        return build_ncompress(source_dir, cc=args.cc, jobs=args.jobs)
    if builder == "tar":
        return build_tar(source_dir, cc=args.cc, jobs=args.jobs)
    if builder == "unarj":
        return build_unarj(source_dir, cc=args.cc, jobs=args.jobs)
    if builder == "unzip":
        return build_unzip(source_dir, cc=args.cc, jobs=args.jobs)
    if builder == "goahead21":
        return build_goahead21(source_dir, cc=args.cc, jobs=args.jobs)
    raise ValueError(f"unknown builder: {builder}")


def main() -> int:
    args = parse_args()
    selected = args.cases or sorted(PACKAGES)
    outputs: list[Path] = []
    for name in selected:
        outputs.extend(build_package(name, PACKAGES[name], args))
    for path in outputs:
        print(f"[+] Built {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
