#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROC_FILE=/proc/mmap_shield

if [[ $(id -u) -ne 0 ]]; then
    echo "Ejecute la suite completa como root: sudo bash tests/run_tests.sh" >&2
    exit 1
fi
if [[ -e "$PROC_FILE" ]] || [[ -d /sys/module/mmap_shield ]]; then
    echo "El modulo ya esta cargado; descarguelo antes de iniciar las pruebas." >&2
    exit 1
fi

make -C "$ROOT_DIR" tests
if [[ ! -f "$ROOT_DIR/mmap_shield.ko" ]]; then
    make -C "$ROOT_DIR"
fi

test_user=${SUDO_USER:-nobody}
if [[ "$test_user" == root ]] || ! id "$test_user" >/dev/null 2>&1; then
    echo "No hay un usuario sin privilegios para ejecutar las pruebas." >&2
    exit 1
fi
test_dir=$(mktemp -d /tmp/mmap-shield-test-XXXXXX)
loaded=0
cleanup() {
    local status=$?
    if [[ $loaded -eq 1 ]]; then
        rmmod mmap_shield || status=1
    fi
    rm -f -- "$test_dir/benign" "$test_dir/protected"
    rmdir -- "$test_dir" || status=1
    exit "$status"
}
trap cleanup EXIT
chown "$test_user" "$test_dir"

insmod "$ROOT_DIR/mmap_shield.ko" enforce_mode=1 block_wx=1 block_dirty_cow=1 block_sensitive=1
loaded=1
printf 'add_path=%s/protected\n' "$test_dir" > "$PROC_FILE"
runuser -u "$test_user" -- env SHIELD_TEST_DIR="$test_dir" "$SCRIPT_DIR/test_runner"

# Verify that mmap-shield, rather than another kernel policy, recorded the denials.
status=$(cat "$PROC_FILE")
for action in 'BLOQUEO_W^X' 'BLOQUEO_SENS' 'DIRTY_COW'; do
    if ! grep -Fq "$action" <<< "$status"; then
        echo "No se encontro el evento de auditoria $action." >&2
        exit 1
    fi
done
printf '%s\n' "$status"
echo "Suite de mmap-shield completada correctamente."
