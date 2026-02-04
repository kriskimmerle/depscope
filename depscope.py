#!/usr/bin/env python3
"""depscope - Dependency Permission & Capability Scanner.

Maps what system capabilities each of your Python dependencies uses:
network access, filesystem, subprocess, crypto, code generation, and more.

Answer the question: "What can my dependencies DO on my system?"

Usage:
    python depscope.py                      # Scan current venv
    python depscope.py --venv /path/to/venv # Scan specific virtualenv
    python depscope.py --site-packages /p   # Scan site-packages directly
    python depscope.py --wheel pkg.whl      # Scan a wheel file
    python depscope.py --requirements req.txt  # Scan from requirements
    python depscope.py --deny network       # Fail if any dep uses network
    python depscope.py --json               # JSON output

Requires: Python 3.9+, zero dependencies.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


__version__ = "0.1.0"

# ── Capability Categories ────────────────────────────────────────────────────

CAPABILITIES: dict[str, dict[str, list[str]]] = {
    "network": {
        "description": "HTTP/TCP/UDP network access",
        "imports": [
            "socket", "http", "http.client", "http.server", "http.cookiejar",
            "urllib", "urllib.request", "urllib.parse", "urllib.error",
            "xmlrpc", "xmlrpc.client", "xmlrpc.server",
            "ftplib", "smtplib", "poplib", "imaplib", "telnetlib",
            "ssl", "email", "email.mime",
            # Third-party
            "requests", "httpx", "aiohttp", "urllib3", "httplib2",
            "websocket", "websockets", "grpc", "paramiko", "fabric",
            "boto3", "botocore", "google.cloud", "azure",
            "twisted", "tornado.httpclient", "flask", "fastapi",
            "django", "starlette", "uvicorn", "gunicorn",
        ],
        "calls": [
            "socket.socket", "socket.create_connection",
            "urlopen", "urlretrieve",
        ],
    },
    "filesystem": {
        "description": "File read/write, directory operations",
        "imports": [
            "shutil", "tempfile", "glob", "fnmatch", "fileinput",
            "filecmp", "mmap", "shelve", "dbm",
            "zipfile", "tarfile", "gzip", "bz2", "lzma",
            "csv", "configparser",
            # Third-party
            "watchdog", "inotify", "pyinotify",
        ],
        "calls": [
            "open", "os.open", "os.read", "os.write",
            "os.mkdir", "os.makedirs", "os.rmdir", "os.remove", "os.unlink",
            "os.rename", "os.replace", "os.link", "os.symlink",
            "os.listdir", "os.scandir", "os.walk",
            "os.chmod", "os.chown", "os.chdir",
            "shutil.copy", "shutil.copy2", "shutil.copytree",
            "shutil.move", "shutil.rmtree",
            "Path.read_text", "Path.write_text",
            "Path.read_bytes", "Path.write_bytes",
            "Path.mkdir", "Path.rmdir", "Path.unlink",
        ],
    },
    "process": {
        "description": "Subprocess execution, OS commands",
        "imports": [
            "subprocess", "multiprocessing",
            "signal",
            # Third-party
            "psutil", "pexpect", "sh",
        ],
        "calls": [
            "subprocess.run", "subprocess.call", "subprocess.check_call",
            "subprocess.check_output", "subprocess.Popen",
            "os.system", "os.popen", "os.exec", "os.execv", "os.execve",
            "os.execvp", "os.execvpe", "os.spawnl", "os.spawnle",
            "os.fork", "os.kill", "os.killpg",
        ],
    },
    "crypto": {
        "description": "Cryptographic operations",
        "imports": [
            "hashlib", "hmac", "secrets",
            "ssl",
            # Third-party
            "cryptography", "nacl", "pynacl",
            "Crypto", "Cryptodome",
            "bcrypt", "passlib", "argon2",
            "jwt", "jose", "jwcrypto",
            "paramiko",
        ],
        "calls": [
            "hashlib.md5", "hashlib.sha1", "hashlib.sha256",
            "hashlib.sha512", "hashlib.new",
            "hmac.new", "hmac.digest",
        ],
    },
    "codegen": {
        "description": "Dynamic code execution, eval/exec",
        "imports": [
            "code", "codeop", "compile", "compileall",
            "importlib",
            # Third-party
            "jinja2", "mako",
        ],
        "calls": [
            "eval", "exec", "compile", "__import__",
            "importlib.import_module",
            "getattr", "setattr", "delattr",
        ],
    },
    "serialization": {
        "description": "Object serialization/deserialization (potential RCE)",
        "imports": [
            "pickle", "shelve", "marshal",
            "yaml",  # PyYAML
            "toml", "tomli", "tomllib",
            # Third-party
            "msgpack", "cbor", "protobuf",
            "dill", "cloudpickle", "joblib",
        ],
        "calls": [
            "pickle.loads", "pickle.load", "pickle.dumps", "pickle.dump",
            "marshal.loads", "marshal.load",
            "yaml.load", "yaml.safe_load", "yaml.unsafe_load",
        ],
    },
    "system": {
        "description": "System info, environment, platform",
        "imports": [
            "platform", "sysconfig", "resource",
            "ctypes", "ctypes.util",
            # Third-party
            "distro",
        ],
        "calls": [
            "os.getenv", "os.environ",
            "os.getuid", "os.getgid", "os.getpid",
            "platform.system", "platform.node",
            "sys.platform",
        ],
    },
    "database": {
        "description": "Database access",
        "imports": [
            "sqlite3",
            # Third-party
            "psycopg2", "psycopg", "asyncpg",
            "pymysql", "mysql", "MySQLdb",
            "pymongo", "motor",
            "redis", "aioredis",
            "sqlalchemy", "peewee", "tortoise",
            "elasticsearch", "opensearchpy",
            "cassandra", "influxdb",
        ],
        "calls": [
            "sqlite3.connect",
        ],
    },
    "gui": {
        "description": "GUI / display",
        "imports": [
            "tkinter", "turtle",
            "webbrowser",
            # Third-party
            "PyQt5", "PyQt6", "PySide2", "PySide6",
            "wx", "kivy", "pyglet", "pygame",
            "matplotlib", "plotly", "bokeh",
            "PIL", "Pillow",
        ],
        "calls": [
            "webbrowser.open",
        ],
    },
    "logging": {
        "description": "Logging and monitoring",
        "imports": [
            "logging",
            # Third-party
            "loguru", "structlog", "sentry_sdk",
        ],
        "calls": [],
    },
}

# Risk level per capability
CAPABILITY_RISK: dict[str, str] = {
    "network": "high",
    "process": "high",
    "codegen": "high",
    "serialization": "high",
    "filesystem": "medium",
    "crypto": "low",
    "database": "medium",
    "system": "medium",
    "gui": "low",
    "logging": "info",
}


@dataclass
class CapabilityRef:
    category: str
    match_type: str  # "import" or "call"
    match_value: str
    file: str
    line: int = 0


@dataclass
class PackageScan:
    name: str
    version: str
    capabilities: dict[str, list[CapabilityRef]] = field(default_factory=dict)
    files_scanned: int = 0
    risk_level: str = "low"


@dataclass
class ScanResult:
    packages: list[PackageScan] = field(default_factory=list)
    total_packages: int = 0
    denied_violations: list[str] = field(default_factory=list)


# ── Package Discovery ────────────────────────────────────────────────────────


def find_site_packages(venv: Optional[Path] = None) -> Optional[Path]:
    """Find site-packages directory."""
    if venv:
        # Check common venv layouts
        for pattern in [
            venv / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages",
            venv / "lib" / "python3" / "site-packages",
            venv / "Lib" / "site-packages",  # Windows
        ]:
            if pattern.is_dir():
                return pattern
        # Glob for any python version
        for p in (venv / "lib").glob("python*/site-packages"):
            if p.is_dir():
                return p
    else:
        # Current interpreter's site-packages
        import site
        paths = site.getsitepackages()
        for p in paths:
            if Path(p).is_dir():
                return Path(p)

    return None


def discover_packages(site_pkgs: Path) -> list[tuple[str, str, Path]]:
    """Discover installed packages from dist-info/egg-info metadata."""
    packages: list[tuple[str, str, Path]] = []
    seen: set[str] = set()

    for meta_dir in sorted(site_pkgs.iterdir()):
        if meta_dir.name.endswith(".dist-info") and meta_dir.is_dir():
            # Parse METADATA
            metadata = meta_dir / "METADATA"
            if not metadata.is_file():
                metadata = meta_dir / "PKG-INFO"
            if not metadata.is_file():
                continue

            name = version = ""
            try:
                for line in metadata.read_text(errors="replace").splitlines():
                    if line.startswith("Name:"):
                        name = line.split(":", 1)[1].strip()
                    elif line.startswith("Version:"):
                        version = line.split(":", 1)[1].strip()
                    if name and version:
                        break
            except (PermissionError, OSError):
                continue

            if not name:
                continue

            norm = re.sub(r"[-_.]+", "-", name).lower()
            if norm in seen:
                continue
            seen.add(norm)

            # Find the package source directory
            top_level = meta_dir / "top_level.txt"
            record = meta_dir / "RECORD"
            pkg_dirs: list[Path] = []

            if top_level.is_file():
                try:
                    for tl in top_level.read_text(errors="replace").splitlines():
                        tl = tl.strip()
                        if tl and (site_pkgs / tl).is_dir():
                            pkg_dirs.append(site_pkgs / tl)
                        elif tl and (site_pkgs / f"{tl}.py").is_file():
                            pkg_dirs.append(site_pkgs / f"{tl}.py")
                except (PermissionError, OSError):
                    pass

            if not pkg_dirs:
                # Fall back: use package name variants
                for variant in [name, name.replace("-", "_"), name.replace("-", "").lower()]:
                    candidate = site_pkgs / variant
                    if candidate.is_dir():
                        pkg_dirs.append(candidate)
                        break
                    candidate_py = site_pkgs / f"{variant}.py"
                    if candidate_py.is_file():
                        pkg_dirs.append(candidate_py)
                        break

            for pkg_dir in pkg_dirs:
                packages.append((name, version, pkg_dir))

    return packages


# ── Capability Scanning ──────────────────────────────────────────────────────


def _build_import_lookup() -> dict[str, str]:
    """Build a mapping from import name to capability category."""
    lookup: dict[str, str] = {}
    for cat, info in CAPABILITIES.items():
        for imp in info["imports"]:
            lookup[imp] = cat
            # Also add top-level module
            top = imp.split(".")[0]
            if top not in lookup:
                lookup[top] = cat
    return lookup


def _build_call_lookup() -> dict[str, str]:
    """Build a mapping from call pattern to capability category."""
    lookup: dict[str, str] = {}
    for cat, info in CAPABILITIES.items():
        for call in info["calls"]:
            lookup[call] = cat
    return lookup


IMPORT_LOOKUP = _build_import_lookup()
CALL_LOOKUP = _build_call_lookup()

# Standard library modules to skip (they're in everything)
STDLIB_SKIP = {
    "os", "sys", "re", "io", "abc", "ast", "dis", "typing", "types",
    "collections", "functools", "itertools", "operator", "copy",
    "warnings", "contextlib", "dataclasses", "enum", "inspect",
    "textwrap", "string", "unicodedata", "pprint", "reprlib",
    "numbers", "decimal", "fractions", "math", "cmath", "statistics",
    "random",  # random is common but not security-relevant for deps
    "datetime", "time", "calendar",
    "json",  # json is ubiquitous
    "pathlib",  # pathlib is used for paths but not risky by itself
    "threading", "concurrent",
    "unittest", "doctest", "pytest",
    "__future__", "builtins", "traceback", "linecache",
    "importlib.metadata", "importlib.resources",
    "atexit", "weakref", "gc",
}


def scan_python_file(filepath: Path, pkg_name: str, site_pkgs: Path) -> list[CapabilityRef]:
    """Scan a single Python file for capability references."""
    refs: list[CapabilityRef] = []

    try:
        source = filepath.read_text(errors="replace")
    except (PermissionError, OSError):
        return refs

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return refs

    rel_path = str(filepath.relative_to(site_pkgs)) if filepath.is_relative_to(site_pkgs) else str(filepath)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name
                top = mod.split(".")[0]
                if top in STDLIB_SKIP:
                    continue
                # Check full qualified name first, then top-level
                cat = IMPORT_LOOKUP.get(mod) or IMPORT_LOOKUP.get(top)
                if cat:
                    refs.append(CapabilityRef(
                        category=cat, match_type="import", match_value=mod,
                        file=rel_path, line=getattr(node, "lineno", 0),
                    ))

        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            top = mod.split(".")[0]
            if top in STDLIB_SKIP:
                continue
            cat = IMPORT_LOOKUP.get(mod) or IMPORT_LOOKUP.get(top)
            if cat:
                refs.append(CapabilityRef(
                    category=cat, match_type="import", match_value=mod,
                    file=rel_path, line=getattr(node, "lineno", 0),
                ))

        elif isinstance(node, ast.Call):
            # Build call name
            call_name = ""
            if isinstance(node.func, ast.Name):
                call_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    call_name = f"{node.func.value.id}.{node.func.attr}"

            if call_name and call_name not in STDLIB_SKIP:
                cat = CALL_LOOKUP.get(call_name)
                if cat:
                    refs.append(CapabilityRef(
                        category=cat, match_type="call", match_value=call_name,
                        file=rel_path, line=getattr(node, "lineno", 0),
                    ))

    return refs


def scan_package(name: str, version: str, pkg_path: Path,
                 site_pkgs: Path) -> PackageScan:
    """Scan a package for capabilities."""
    result = PackageScan(name=name, version=version)

    if pkg_path.is_file() and pkg_path.suffix == ".py":
        # Single-file package
        refs = scan_python_file(pkg_path, name, site_pkgs)
        for ref in refs:
            result.capabilities.setdefault(ref.category, []).append(ref)
        result.files_scanned = 1
    elif pkg_path.is_dir():
        for py_file in sorted(pkg_path.rglob("*.py")):
            # Skip test files
            if "test" in py_file.parts or py_file.name.startswith("test_"):
                continue
            refs = scan_python_file(py_file, name, site_pkgs)
            for ref in refs:
                result.capabilities.setdefault(ref.category, []).append(ref)
            result.files_scanned += 1

    # Determine risk level
    if result.capabilities:
        max_risk = "info"
        risk_order = {"info": 0, "low": 1, "medium": 2, "high": 3}
        for cat in result.capabilities:
            cat_risk = CAPABILITY_RISK.get(cat, "info")
            if risk_order.get(cat_risk, 0) > risk_order.get(max_risk, 0):
                max_risk = cat_risk
        result.risk_level = max_risk

    return result


def scan_wheel(wheel_path: Path) -> PackageScan:
    """Scan a wheel file for capabilities."""
    name = version = ""
    # Parse name from wheel filename
    parts = wheel_path.stem.split("-")
    if len(parts) >= 2:
        name = parts[0]
        version = parts[1]

    result = PackageScan(name=name, version=version)

    try:
        with zipfile.ZipFile(wheel_path) as zf:
            for info in zf.infolist():
                if info.filename.endswith(".py"):
                    try:
                        source = zf.read(info.filename).decode("utf-8", errors="replace")
                        tree = ast.parse(source)
                    except (SyntaxError, Exception):
                        continue

                    result.files_scanned += 1

                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                mod = alias.name
                                top = mod.split(".")[0]
                                if top in STDLIB_SKIP:
                                    continue
                                cat = IMPORT_LOOKUP.get(mod) or IMPORT_LOOKUP.get(top)
                                if cat:
                                    result.capabilities.setdefault(cat, []).append(
                                        CapabilityRef(
                                            category=cat, match_type="import",
                                            match_value=mod, file=info.filename,
                                            line=getattr(node, "lineno", 0),
                                        )
                                    )

                        elif isinstance(node, ast.ImportFrom):
                            mod = node.module or ""
                            top = mod.split(".")[0]
                            if top in STDLIB_SKIP:
                                continue
                            cat = IMPORT_LOOKUP.get(mod) or IMPORT_LOOKUP.get(top)
                            if cat:
                                result.capabilities.setdefault(cat, []).append(
                                    CapabilityRef(
                                        category=cat, match_type="import",
                                        match_value=mod, file=info.filename,
                                        line=getattr(node, "lineno", 0),
                                    )
                                )

                        elif isinstance(node, ast.Call):
                            call_name = ""
                            if isinstance(node.func, ast.Name):
                                call_name = node.func.id
                            elif isinstance(node.func, ast.Attribute):
                                if isinstance(node.func.value, ast.Name):
                                    call_name = f"{node.func.value.id}.{node.func.attr}"
                            if call_name:
                                cat = CALL_LOOKUP.get(call_name)
                                if cat:
                                    result.capabilities.setdefault(cat, []).append(
                                        CapabilityRef(
                                            category=cat, match_type="call",
                                            match_value=call_name, file=info.filename,
                                            line=getattr(node, "lineno", 0),
                                        )
                                    )
    except (zipfile.BadZipFile, Exception):
        pass

    # Determine risk
    if result.capabilities:
        risk_order = {"info": 0, "low": 1, "medium": 2, "high": 3}
        max_risk = "info"
        for cat in result.capabilities:
            cat_risk = CAPABILITY_RISK.get(cat, "info")
            if risk_order.get(cat_risk, 0) > risk_order.get(max_risk, 0):
                max_risk = cat_risk
        result.risk_level = max_risk

    return result


# ── Formatting ───────────────────────────────────────────────────────────────

RISK_COLORS = {
    "high": "\033[91m", "medium": "\033[93m",
    "low": "\033[36m", "info": "\033[90m",
}
CAP_EMOJI = {
    "network": "🌐", "filesystem": "📁", "process": "⚙️",
    "crypto": "🔐", "codegen": "💉", "serialization": "📦",
    "system": "🖥️", "database": "🗄️", "gui": "🖼️", "logging": "📝",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def format_results(result: ScanResult, verbose: bool = False,
                   use_color: bool = True) -> str:
    b = BOLD if use_color else ""
    r = RESET if use_color else ""
    lines: list[str] = []

    lines.append(f"\n{b}🔬 depscope — Dependency Capability Scanner{r}")
    lines.append(f"{'─' * 60}")

    if not result.packages:
        lines.append(f"\n  No packages found to scan.")
        lines.append("")
        return "\n".join(lines)

    # Summary table
    lines.append(f"\n  {'Package':<30} {'Version':<12} {'Risk':<8} {'Capabilities'}")
    lines.append(f"  {'─' * 30} {'─' * 12} {'─' * 8} {'─' * 30}")

    for pkg in result.packages:
        if not pkg.capabilities:
            continue
        rc = RISK_COLORS.get(pkg.risk_level, "") if use_color else ""
        caps_str = ", ".join(
            f"{CAP_EMOJI.get(c, '•')} {c}" for c in sorted(pkg.capabilities.keys())
        )
        risk_label = pkg.risk_level.upper()
        lines.append(
            f"  {pkg.name:<30} {pkg.version:<12} {rc}{risk_label:<8}{r} {caps_str}"
        )

    # Stats
    total = len(result.packages)
    with_caps = sum(1 for p in result.packages if p.capabilities)
    high_risk = sum(1 for p in result.packages if p.risk_level == "high")
    med_risk = sum(1 for p in result.packages if p.risk_level == "medium")

    lines.append(f"\n{'─' * 60}")
    lines.append(
        f"  Packages: {b}{total}{r}  |  "
        f"With capabilities: {b}{with_caps}{r}  |  "
        f"High risk: {b}{high_risk}{r}  |  "
        f"Medium: {b}{med_risk}{r}"
    )

    # Capability summary
    cap_counts: dict[str, int] = {}
    for pkg in result.packages:
        for cat in pkg.capabilities:
            cap_counts[cat] = cap_counts.get(cat, 0) + 1

    if cap_counts:
        lines.append(f"\n  {b}Capability Summary:{r}")
        for cat, count in sorted(cap_counts.items(), key=lambda x: -x[1]):
            emoji = CAP_EMOJI.get(cat, "•")
            risk = CAPABILITY_RISK.get(cat, "info")
            rc = RISK_COLORS.get(risk, "") if use_color else ""
            desc = CAPABILITIES[cat]["description"]
            lines.append(f"    {emoji} {cat:<16} {rc}[{risk}]{r}  {count} packages — {desc}")

    # Verbose: per-package details
    if verbose:
        lines.append(f"\n  {b}Detailed References:{r}")
        for pkg in result.packages:
            if not pkg.capabilities:
                continue
            lines.append(f"\n    {b}{pkg.name} {pkg.version}{r}  ({pkg.files_scanned} files)")
            for cat, refs in sorted(pkg.capabilities.items()):
                # Deduplicate by match_value
                seen_vals: set[str] = set()
                unique_refs = []
                for ref in refs:
                    if ref.match_value not in seen_vals:
                        seen_vals.add(ref.match_value)
                        unique_refs.append(ref)

                lines.append(f"      {CAP_EMOJI.get(cat, '•')} {cat}:")
                for ref in unique_refs[:5]:
                    lines.append(f"        {ref.match_type}: {ref.match_value}  ({ref.file}:{ref.line})")
                if len(unique_refs) > 5:
                    lines.append(f"        ... and {len(unique_refs) - 5} more")

    # Denied violations
    if result.denied_violations:
        lines.append(f"\n  {RISK_COLORS.get('high', '')}❌ POLICY VIOLATIONS:{r}")
        for v in result.denied_violations:
            lines.append(f"    • {v}")

    lines.append("")
    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    return json.dumps({
        "tool": "depscope",
        "version": __version__,
        "total_packages": result.total_packages,
        "denied_violations": result.denied_violations,
        "packages": [
            {
                "name": pkg.name,
                "version": pkg.version,
                "risk_level": pkg.risk_level,
                "files_scanned": pkg.files_scanned,
                "capabilities": {
                    cat: [
                        {
                            "type": ref.match_type,
                            "value": ref.match_value,
                            "file": ref.file,
                            "line": ref.line,
                        }
                        for ref in refs
                    ]
                    for cat, refs in pkg.capabilities.items()
                },
            }
            for pkg in result.packages if pkg.capabilities
        ],
    }, indent=2)


# ── CLI ──────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="depscope",
        description="Dependency Permission & Capability Scanner — "
                    "map what your Python dependencies can DO.",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--venv", type=str, help="Path to virtualenv")
    group.add_argument("--site-packages", type=str, help="Path to site-packages dir")
    group.add_argument("--wheel", type=str, help="Path to .whl file to scan")
    group.add_argument("--package", type=str, help="Scan a single installed package by name")

    parser.add_argument("--deny", type=str, nargs="+",
                        help="Fail if any package uses these capabilities (e.g., network process)")
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show per-package details")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--list-capabilities", action="store_true",
                        help="List all capability categories")
    parser.add_argument("--version", action="version", version=f"depscope {__version__}")

    args = parser.parse_args()

    if args.list_capabilities:
        print(f"\n{'Category':<18} {'Risk':<8} {'Description'}")
        print(f"{'─' * 18} {'─' * 8} {'─' * 40}")
        for cat, info in CAPABILITIES.items():
            risk = CAPABILITY_RISK.get(cat, "info")
            print(f"{CAP_EMOJI.get(cat, '•')} {cat:<15} {risk:<8} {info['description']}")
        print()
        return 0

    use_color = not args.no_color and not args.json_output and sys.stdout.isatty()

    # Single wheel scan
    if args.wheel:
        whl = Path(args.wheel)
        if not whl.is_file():
            print(f"Error: {whl} not found", file=sys.stderr)
            return 1
        pkg_scan = scan_wheel(whl)
        scan_result = ScanResult(packages=[pkg_scan], total_packages=1)
    else:
        # Find site-packages
        site_pkgs = None
        if args.site_packages:
            site_pkgs = Path(args.site_packages)
        elif args.venv:
            site_pkgs = find_site_packages(Path(args.venv))
        else:
            site_pkgs = find_site_packages()

        if not site_pkgs or not site_pkgs.is_dir():
            print("Error: Could not find site-packages directory. "
                  "Use --venv or --site-packages.", file=sys.stderr)
            return 1

        packages = discover_packages(site_pkgs)

        if args.package:
            # Filter to a single package
            norm = re.sub(r"[-_.]+", "-", args.package).lower()
            packages = [(n, v, p) for n, v, p in packages
                        if re.sub(r"[-_.]+", "-", n).lower() == norm]
            if not packages:
                print(f"Error: Package '{args.package}' not found", file=sys.stderr)
                return 1

        scans: list[PackageScan] = []
        for name, version, pkg_path in packages:
            pkg_scan = scan_package(name, version, pkg_path, site_pkgs)
            scans.append(pkg_scan)

        scan_result = ScanResult(packages=scans, total_packages=len(scans))

    # Check denied capabilities
    if args.deny:
        for pkg in scan_result.packages:
            for denied_cap in args.deny:
                if denied_cap in pkg.capabilities:
                    scan_result.denied_violations.append(
                        f"{pkg.name} uses denied capability: {denied_cap}"
                    )

    if args.json_output:
        print(format_json(scan_result))
    else:
        print(format_results(scan_result, verbose=args.verbose, use_color=use_color))

    if scan_result.denied_violations:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
