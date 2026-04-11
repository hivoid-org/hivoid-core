#!/usr/bin/env bash
# HiVoid Build Automation
# Usage: ./build.sh [command] [version]

set -euo pipefail
IFS=$'\n\t'

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

readonly ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly SELF="$(basename "$0")"
readonly DIST_DIR="${ROOT_DIR}/dist"
readonly SCRIPTS_DIR="${ROOT_DIR}/scripts"
readonly LOCK_FILE="/tmp/${SELF}.lock"
readonly LOG_DIR="${ROOT_DIR}/logs"

readonly ESC=$'\033'
readonly   RED="${ESC}[0;31m"
readonly YELLOW="${ESC}[0;33m"
readonly  GREEN="${ESC}[0;32m"
readonly   BLUE="${ESC}[0;34m"
readonly   CYAN="${ESC}[0;36m"
readonly   BOLD="${ESC}[1m"
readonly     NC="${ESC}[0m"

# Feature flags (override via environment)
DRY_RUN="${DRY_RUN:-0}"
LOG_OUTPUT="${LOG_OUTPUT:-0}"

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

log()    { echo -e "${BLUE}  →${NC} $*"; }
ok()     { echo -e "${GREEN}  ✓${NC} $*"; }
warn()   { echo -e "${YELLOW}  ⚠${NC} $*" >&2; }
die()    { echo -e "${RED}  ✗ Error:${NC} $*" >&2; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
# Lock — prevents concurrent builds
# ─────────────────────────────────────────────────────────────────────────────

_acquire_lock() {
    exec 9>"${LOCK_FILE}"
    flock -n 9 || die "Another build is already running (lock: ${LOCK_FILE})."
}

_release_lock() {
    flock -u 9 2>/dev/null || true
    exec 9>&- 2>/dev/null || true
}

# ─────────────────────────────────────────────────────────────────────────────
# Trap — cleanup and failure notice on unexpected exit
# ─────────────────────────────────────────────────────────────────────────────

_on_exit() {
    local code="$1"
    if [[ "${code}" -ne 0 ]]; then
        echo ""
        warn "Build exited with code ${code} — artifacts in ${DIST_DIR}/ may be incomplete."
        [[ "${LOG_OUTPUT}" == "1" ]] && warn "Full log: ${_LOG_FILE:-}"
    fi
    _release_lock
}

trap '_on_exit $?' EXIT

# ─────────────────────────────────────────────────────────────────────────────
# Log file (opt-in via LOG_OUTPUT=1)
# ─────────────────────────────────────────────────────────────────────────────

_LOG_FILE=""

_setup_log() {
    [[ "${LOG_OUTPUT}" != "1" ]] && return
    mkdir -p "${LOG_DIR}"
    _LOG_FILE="${LOG_DIR}/build-$(date +%Y%m%d-%H%M%S).log"
    exec > >(tee -a "${_LOG_FILE}") 2>&1
    log "Logging to ${_LOG_FILE}"
}

# ─────────────────────────────────────────────────────────────────────────────
# Dry-run wrapper
# ─────────────────────────────────────────────────────────────────────────────

# Use `run cmd args…` instead of calling commands directly in build steps.
# With DRY_RUN=1 it prints what would be executed without running it.
run() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "${YELLOW}  [dry-run]${NC} $*"
    else
        "$@"
    fi
}

section() {
    echo ""
    echo -e "${BOLD}${BLUE}  ── $* ──────────────────────────────────────────────${NC}"
    [[ "${DRY_RUN}" == "1" ]] && echo -e "${YELLOW}  [dry-run mode]${NC}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

require_cmd() {
    local cmd="$1" hint="${2:-}"
    command -v "${cmd}" >/dev/null 2>&1 || {
        die "'${cmd}' not found in PATH.${hint:+ Hint: ${hint}}"
    }
}

require_docker() {
    require_cmd docker "Install from https://docker.com"
    docker info >/dev/null 2>&1    || die "Docker daemon is not running."
    docker buildx version >/dev/null 2>&1 || die "Docker Buildx not available — upgrade Docker."
}

# Finds the Go binary across common install locations (including Windows paths).
find_go() {
    local candidates=(
        go go.exe
        /usr/local/go/bin/go
        /usr/bin/go
        "/mnt/c/Program Files/Go/bin/go.exe"
        "/c/Program Files/Go/bin/go.exe"
    )
    local bin
    for bin in "${candidates[@]}"; do
        if command -v "${bin}" >/dev/null 2>&1; then command -v "${bin}"; return; fi
        if [[ -x "${bin}" ]];                    then echo "${bin}";      return; fi
    done
    die "Go not found. Install from https://go.dev/dl/"
}

# Resolves the build version: CLI arg → VERSION env → interactive prompt.
resolve_version() {
    local provided="${1:-}"
    [[ -n "${provided}" ]]     && { echo "${provided}"; return; }
    [[ -n "${VERSION:-}" ]]    && { echo "${VERSION}";  return; }
    local v
    read -r -p "  Build version (default: dev): " v
    echo "${v:-dev}"
}

elapsed() {
    local start="$1" end="$2"
    echo $(( end - start ))s
}

# ─────────────────────────────────────────────────────────────────────────────
# Build Steps
# ─────────────────────────────────────────────────────────────────────────────

cmd_test() {
    section "Tests"
    local go_bin t0 t1
    go_bin="$(find_go)"

    log "Go: ${go_bin}"
    log "Running test suite..."
    t0=$(date +%s)

    (cd "${ROOT_DIR}" && run "${go_bin}" test ./... -count=1 -v) \
        2>&1 | sed 's/^/    │ /'

    t1=$(date +%s)
    ok "All tests passed ($(elapsed "${t0}" "${t1}"))"
}

_build_platform() {
    local label="$1" script="$2" version="$3"
    section "${label}"
    require_docker
    log "Version: ${version}"
    # Sub-script output is indented to stay visually separate from build.sh lines
    (cd "${ROOT_DIR}" && run env VERSION="${version}" bash "${SCRIPTS_DIR}/${script}") \
        2>&1 | sed 's/^/    │ /'
    ok "${label} done"
}

cmd_build_desktop() { _build_platform "Desktop (Linux + Windows)"   build-all.sh     "${1}"; }
cmd_build_ffi()     { _build_platform "FFI Shared Libraries"        build-ffi.sh     "${1}"; }
cmd_build_android() { _build_platform "Android Libraries"           build-android.sh "${1}"; }

cmd_build_all() {
    local version="$1" t0 t1
    section "All Platforms"
    log "Version: ${version} — Desktop · FFI · Android"
    t0=$(date +%s)

    cmd_build_desktop "${version}"
    cmd_build_ffi     "${version}"
    cmd_build_android "${version}"

    t1=$(date +%s)
    section "Summary"
    ok "All platforms built ($(elapsed "${t0}" "${t1}"))"
    _print_artifacts
}

cmd_compile() {
    local version="$1" t0 t1
    section "Compile Pipeline"
    log "Version: ${version} — Test → Desktop → FFI → Android"
    t0=$(date +%s)

    cmd_test
    cmd_build_all "${version}"

    t1=$(date +%s)
    section "Compile Summary"
    ok "Tests passed"
    ok "All platforms built"
    ok "Total time: $(elapsed "${t0}" "${t1}")"
    _print_artifacts
}

_print_artifacts() {
    [[ -d "${DIST_DIR}" ]] || return
    echo ""
    log "Artifacts in ${DIST_DIR}/:"
    ls -lh "${DIST_DIR}/" 2>/dev/null | tail -n +2 | sed 's/^/      /' \
        || echo "      (none)"
}

cmd_clean() {
    section "Clean"
    if [[ -d "${DIST_DIR}" ]]; then
        log "Removing ${DIST_DIR}/"
        run rm -rf "${DIST_DIR}"
        ok "Done"
    else
        log "Nothing to clean"
    fi
}

cmd_status() {
    section "Environment"

    echo -e "  ${BOLD}Go${NC}"
    local go_bin
    if go_bin="$(find_go 2>/dev/null)"; then
        ok "$(${go_bin} version 2>/dev/null)"
        log "  at ${go_bin}"
    else
        echo -e "  ${RED}  ✗${NC} Not found"
    fi

    echo ""
    echo -e "  ${BOLD}Docker${NC}"
    if command -v docker >/dev/null 2>&1; then
        ok "$(docker --version 2>/dev/null)"
        if docker info >/dev/null 2>&1; then
            ok "Daemon running"
            docker buildx version >/dev/null 2>&1 \
                && ok "Buildx: $(docker buildx version 2>/dev/null | head -1)" \
                || warn "Buildx not available"
        else
            echo -e "  ${RED}  ✗${NC} Daemon not running"
        fi
    else
        echo -e "  ${RED}  ✗${NC} Not found"
    fi

    echo ""
    echo -e "  ${BOLD}Artifacts${NC}"
    if [[ -d "${DIST_DIR}" ]]; then
        local n
        n=$(find "${DIST_DIR}" -type f 2>/dev/null | wc -l)
        ok "${DIST_DIR}/ (${n} files)"
        [[ "${n}" -gt 0 ]] && ls -lht "${DIST_DIR}" 2>/dev/null \
            | head -4 | tail -3 | sed 's/^/      /'
    else
        warn "No artifacts found"
    fi
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Interactive Menu
# ─────────────────────────────────────────────────────────────────────────────

cmd_menu() {
    local choice version

    while true; do
        clear
        echo ""
        echo -e "${CYAN}${BOLD}  HiVoid Build Automation${NC}"
        echo -e "${CYAN}  ─────────────────────────────${NC}"
        echo ""
        echo -e "  ${CYAN}1${NC}  Run tests"
        echo -e "  ${CYAN}2${NC}  Compile all  (test + build)"
        echo -e "  ${CYAN}3${NC}  Build all platforms"
        echo -e "  ${CYAN}4${NC}  Build desktop"
        echo -e "  ${CYAN}5${NC}  Build FFI"
        echo -e "  ${CYAN}6${NC}  Build Android"
        echo -e "  ${CYAN}7${NC}  Clean artifacts"
        echo -e "  ${CYAN}8${NC}  Environment status"
        echo -e "  ${CYAN}0${NC}  Exit"
        echo ""
        read -r -p "  › " choice

        case "${choice}" in
            1) _acquire_lock; _setup_log; cmd_test;                                              _release_lock ;;
            2) _acquire_lock; _setup_log; version="$(resolve_version "")"; cmd_compile "${version}";       _release_lock ;;
            3) _acquire_lock; _setup_log; version="$(resolve_version "")"; cmd_build_all "${version}";     _release_lock ;;
            4) _acquire_lock; _setup_log; version="$(resolve_version "")"; cmd_build_desktop "${version}"; _release_lock ;;
            5) _acquire_lock; _setup_log; version="$(resolve_version "")"; cmd_build_ffi "${version}";     _release_lock ;;
            6) _acquire_lock; _setup_log; version="$(resolve_version "")"; cmd_build_android "${version}"; _release_lock ;;
            7) _acquire_lock;             cmd_clean;                                             _release_lock ;;
            8) cmd_status ;;
            0) echo ""; log "Bye."; exit 0 ;;
            *) warn "Unknown option: ${choice}" ;;
        esac

        echo ""
        read -r -p "  Press Enter to continue..."
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# Usage
# ─────────────────────────────────────────────────────────────────────────────

cmd_usage() {
    cat <<EOF

${BOLD}Usage:${NC}
  ./${SELF}                     Interactive menu
  ./${SELF} <command> [version]

${BOLD}Commands:${NC}
  test                        Run test suite
  compile      [version]      Test + build all platforms
  build-all    [version]      Build all platforms
  build-desktop [version]     Build Linux/Windows binaries
  build-ffi    [version]      Build FFI shared libraries
  build-android [version]     Build Android shared libraries
  clean                       Remove build artifacts
  status                      Show environment status
  help                        Show this message

${BOLD}Version:${NC}
  Resolved in order: CLI arg → \$VERSION env → interactive prompt

${BOLD}Environment Variables:${NC}
  VERSION=<tag>               Set build version (skips prompt)
  DRY_RUN=1                   Print commands without executing them
  LOG_OUTPUT=1                Tee all output to logs/build-<timestamp>.log

${BOLD}Examples:${NC}
  ./${SELF} test
  ./${SELF} compile 1.2.0
  VERSION=1.2.0 ./${SELF} build-all
  DRY_RUN=1 ./${SELF} compile 1.2.0
  LOG_OUTPUT=1 ./${SELF} compile 1.2.0

EOF
}

# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

main() {
    local cmd="${1:-}" version

    # Commands that don't need a lock or log file
    case "${cmd}" in
        "")             cmd_menu;  return ;;
        status)         cmd_status; return ;;
        help|-h|--help) cmd_usage;  return ;;
    esac

    _acquire_lock
    _setup_log

    case "${cmd}" in
        test)           cmd_test ;;
        compile)        version="$(resolve_version "${2:-}")"; cmd_compile "${version}" ;;
        build-all)      version="$(resolve_version "${2:-}")"; cmd_build_all "${version}" ;;
        build-desktop)  version="$(resolve_version "${2:-}")"; cmd_build_desktop "${version}" ;;
        build-ffi)      version="$(resolve_version "${2:-}")"; cmd_build_ffi "${version}" ;;
        build-android)  version="$(resolve_version "${2:-}")"; cmd_build_android "${version}" ;;
        clean)          cmd_clean ;;
        *)              die "Unknown command: '${cmd}'. Run './${SELF} help' for usage." ;;
    esac
}

main "$@"