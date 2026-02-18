# BUMP_LPE - Linux Privilege Escalation Toolkit

Automated Linux privilege escalation enumeration and exploitation tool.

## Quick Start

```bash
curl -sSL https://raw.githubusercontent.com/44pie/BUMP_LPE/main/bump_lpe.sh | bash
```

## Features

- **80+ GTFOBins** mappings for SUID/sudo exploitation
- **Kernel CVE** detection (Dirty Pipe, PwnKit, Dirty COW, OverlayFS, Netfilter, GameOver(lay))
- **Auto-exploitation** with `--exploit` flag
- Sudo, SUID, capabilities, cron, Docker, NFS, credentials hunting
- LD_PRELOAD, PATH hijacking, writable files exploitation
- Container escape (Docker socket, cgroup)
- Password and credential hunting

## Usage

```bash
# Enumerate only (default)
./bump_lpe.sh

# Auto-exploit found vectors
./bump_lpe.sh --exploit

# Aggressive mode (kernel exploits, may crash system)
./bump_lpe.sh --exploit --aggressive

# Verbose output
./bump_lpe.sh -v

# Quiet mode
./bump_lpe.sh --quiet
```

## Flags

| Flag | Description |
|------|-------------|
| `--exploit` | Auto-exploit found vectors |
| `--scan-only` | Enumerate only |
| `--aggressive` | Try kernel exploits (may crash system) |
| `--verbose` / `-v` | Detailed output |
| `--quiet` | Minimal output |
| `--no-color` | Disable colors |
| `--help` | Show help |
