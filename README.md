# CMMCMAP — CMMC Level 2 practice mapper — stack-aware SSP skeleton generator

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `federal`

[![PyPI](https://img.shields.io/pypi/v/cognis-cmmcmap.svg)](https://pypi.org/project/cognis-cmmcmap/)
[![CI](https://github.com/cognis-digital/cmmcmap/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/cmmcmap/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)

CMMC Level 2 practice mapper — stack-aware SSP skeleton generator.

## Install

```bash
pip install cognis-cmmcmap
```

For local development from this repo:

```bash
pip install -e .
```

## Quick start

```bash
cmmcmap --version
cmmcmap scan demos/                          # run against bundled demo
cmmcmap scan demos/ --format sarif --out r.sarif --fail-on high
cmmcmap mcp                                   # start as MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Every scenario folder includes a `SCENARIO.md` describing what it represents and what findings to expect.

- `demos/01-defense-contractor-pre-audit/` — see [`SCENARIO.md`](demos/01-defense-contractor-pre-audit/SCENARIO.md)
- `demos/02-cui-handling-control-scope/` — see [`SCENARIO.md`](demos/02-cui-handling-control-scope/SCENARIO.md)
- `demos/03-small-prime-3-month-prep/` — see [`SCENARIO.md`](demos/03-small-prime-3-month-prep/SCENARIO.md)

## How it fits the Cognis Neural Suite

This tool is one of 52 in the [Cognis Neural Suite](https://github.com/cognis-digital). The full suite + launcher lives at:

- Suite landing: https://cognis.digital
- All 52 repos: https://github.com/cognis-digital
- Cognis.Studio (Enterprise AI Workforce, MCP host): https://cognis.studio

Every Suite tool ships an MCP server, so Cognis.Studio agents can call them as scoped capabilities.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md) for the collaboration-pull model.

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
