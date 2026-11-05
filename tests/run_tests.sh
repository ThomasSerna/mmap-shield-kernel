#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROC_FILE=/proc/mmap_shield
MODULE_KO="$ROOT_DIR/mmap_shield.ko"
MODULE_ARGS=(enforce_mode=1 block_wx=1 block_dirty_cow=1 block_sensitive=1)
# Loader command; e.g. INSMOD="insmod -f" when the build tree used another compiler (see README)
INSMOD=${INSMOD:-insmod}

if [[ $(id -u) -ne 0 ]]; then
    echo "Ejecute la suite completa como root: sudo bash tests/run_tests.sh" >&2
    exit 1
fi
if [[ -e "$PROC_FILE" ]] || [[ -d /sys/module/mmap_shield ]]; then
    echo "El modulo ya esta cargado; descarguelo antes de iniciar las pruebas." >&2
    exit 1
fi

make -C "$ROOT_DIR" tests
if [[ ! -f "$MODULE_KO" ]]; then
    make -C "$ROOT_DIR"
fi

test_user=${SUDO_USER:-nobody}
if [[ "$test_user" == root ]] || ! id "$test_user" >/dev/null 2>&1; then
    echo "No hay un usuario sin privilegios para ejecutar las pruebas." >&2
    exit 1
fi
test_dir=$(mktemp -d /tmp/mmap-shield-test-XXXXXX)
loaded=0
stress_pid=""
cleanup() {
    local status=$?
    if [[ -n "$stress_pid" ]]; then
        kill "$stress_pid" 2>/dev/null || true
        wait "$stress_pid" 2>/dev/null || true
    fi
    if [[ $loaded -eq 1 ]]; then
        rmmod mmap_shield || status=1
    fi
    rm -f -- "$test_dir"/{benign,protected,alias,root_protected,victim,decoy}
    rmdir -- "$test_dir" || status=1
    exit "$status"
}
trap cleanup EXIT
chown "$test_user" "$test_dir"

as_user() {
    runuser -u "$test_user" -- "$@"
}

# The protected files exist before they are registered, so the module records
# their inode and not only their path.
as_user touch "$test_dir/benign" "$test_dir/protected"

# Marker to inspect only the kernel messages produced by this run
kmsg_marker="mmap-shield-tests: inicio $$ $(date +%s)"
echo "$kmsg_marker" > /dev/kmsg

$INSMOD "$MODULE_KO" "${MODULE_ARGS[@]}"
loaded=1
printf 'add_path=%s/protected\n' "$test_dir" > "$PROC_FILE"

echo "==> Fase 1: pruebas funcionales y de evasion como '$test_user'"
as_user env SHIELD_TEST_DIR="$test_dir" "$SCRIPT_DIR/test_runner"

# Verify that mmap-shield, rather than another kernel policy, recorded the denials.
status=$(cat "$PROC_FILE")
for action in 'BLOQUEO_W^X' 'BLOQUEO_SENS' 'DIRTY_COW' 'BLOQUEO_SHARED' 'BLOQUEO_ALIAS_WX' 'MPROTECT'; do
    if ! grep -Fq -- "$action" <<< "$status"; then
        echo "No se encontro el evento de auditoria $action." >&2
        exit 1
    fi
done
printf '%s\n' "$status"

echo "==> Fase 2: uso normal del sistema con el modulo cargado (falsos positivos)"
for cmd in "ls /" "bash -c true" "python3 -c pass" "gcc --version" "make --version" "git --version"; do
    command -v "${cmd%% *}" >/dev/null 2>&1 || continue
    # shellcheck disable=SC2086 # the command line is split on purpose
    if as_user $cmd > /dev/null 2>&1; then
        echo "  [OK] $cmd"
    else
        echo "  [FALLO] '$cmd' no funciona con el modulo cargado" >&2
        exit 1
    fi
done

echo "==> Verificacion de mensajes del kernel"
if dmesg | sed -n "/$kmsg_marker/,\$p" | grep -E "Missing ENDBR|BUG:|Oops|general protection fault|Call Trace"; then
    echo "El kernel registro errores durante las pruebas." >&2
    exit 1
fi
echo "  Sin errores del kernel (Missing ENDBR, BUG, Oops) desde el inicio de las pruebas."

echo "Suite de mmap-shield completada correctamente."
