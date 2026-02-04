# depscope

**Dependency Permission & Capability Scanner** — map what your Python dependencies can actually DO on your system.

When you `pip install` a package, what capabilities does it gain? Network access? Subprocess execution? Filesystem writes? Serialization (potential RCE)? **depscope tells you.**

Zero dependencies. Python 3.9+.

## Quick Start

```bash
# Scan current virtualenv
python depscope.py

# Scan a single package
python depscope.py --package requests

# Verbose: show exact import/call references
python depscope.py -v

# Policy gate: fail if any dep uses network
python depscope.py --deny network process

# Scan a wheel before installing
python depscope.py --wheel package-1.0.0.whl

# JSON output
python depscope.py --json
```

## Capabilities Tracked

| Category | Risk | What It Detects |
|----------|------|-----------------|
| 🌐 network | HIGH | HTTP clients, sockets, web frameworks, cloud SDKs |
| ⚙️ process | HIGH | subprocess, os.system, os.exec*, os.fork |
| 💉 codegen | HIGH | eval, exec, compile, __import__, dynamic imports |
| 📦 serialization | HIGH | pickle, marshal, yaml.load (potential RCE vectors) |
| 📁 filesystem | MEDIUM | File I/O, shutil, tempfile, archives |
| 🗄️ database | MEDIUM | SQLite, PostgreSQL, MySQL, MongoDB, Redis |
| 🖥️ system | MEDIUM | Platform info, env vars, ctypes |
| 🔐 crypto | LOW | hashlib, ssl, cryptography |
| 🖼️ gui | LOW | tkinter, Qt, matplotlib |
| 📝 logging | INFO | logging, loguru |

## Example Output

```
🔬 depscope — Dependency Capability Scanner
────────────────────────────────────────────────────────────

  Package                        Version      Risk     Capabilities
  ────────────────────────────── ──────────── ──────── ──────────────────────────────
  requests                       2.31.0       HIGH     🔐 crypto, 📁 filesystem, 🌐 network
  flask                          3.0.0        HIGH     💉 codegen, 📁 filesystem, 📝 logging, 🌐 network
  cryptography                   41.0.0       HIGH     🔐 crypto, 📁 filesystem, ⚙️ process
  pyyaml                         6.0.1        HIGH     📦 serialization

────────────────────────────────────────────────────────────
  Packages: 12  |  With capabilities: 8  |  High risk: 4  |  Medium: 2

  Capability Summary:
    🌐 network          [high]  3 packages — HTTP/TCP/UDP network access
    📦 serialization    [high]  2 packages — Object serialization/deserialization
    📁 filesystem       [medium]  5 packages — File read/write, directory operations
```

## Policy Enforcement

Use `--deny` to enforce capability policies in CI:

```bash
# No dep should use network or subprocess
python depscope.py --deny network process

# Exit code: 1 if any package violates policy
```

```yaml
# GitHub Actions
- name: Dependency capability audit
  run: python depscope.py --deny process serialization --json
```

## Options

```
--venv PATH           Scan specific virtualenv
--site-packages PATH  Scan site-packages directly
--wheel FILE          Scan a .whl file
--package NAME        Scan a single installed package
--deny CAP [CAP ...]  Fail if any package uses these capabilities
--json                JSON output
--verbose, -v         Show per-package import/call references
--no-color            Disable colors
--list-capabilities   Show all capability categories
--version             Show version
```

## Why This Exists

- **OWASP Agentic AI ASI-01 (Excessive Agency)**: AI agents install packages blindly — depscope reveals what those packages can do
- **Supply chain transparency**: Know what capabilities your dependency tree gains before you deploy
- **Sandbox verification**: Confirm that packages in a restricted environment don't use forbidden capabilities
- **Security review**: Quickly audit what a new dependency brings to your project

GuardDog detects *malicious* packages. depscope maps *capabilities* — neutral, factual, per-package.

## License

MIT
