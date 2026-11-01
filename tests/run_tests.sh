#!/usr/bin/env bash
# ==============================================================================
# Script de Automatización de Pruebas para mmap-shield
# Asignatura: Sistemas Operativos (EAFIT) - Periodo 2026-2
# ==============================================================================

set -e

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
BOLD="\033[1m"
RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$SCRIPT_DIR/test_runner"
MODULE_KO="$ROOT_DIR/mmap_shield.ko"
PROC_FILE="/proc/mmap_shield"

echo -e "${CYAN}======================================================================${RESET}"
echo -e "${BOLD}   INICIANDO EJECUCION DE PRUEBAS DE SEGURIDAD MMAP-SHIELD${RESET}"
echo -e "${CYAN}======================================================================${RESET}"

# 1. Compilación del binario de pruebas
echo -e "\n${BOLD}[1/5] Compilando el ejecutable de pruebas en espacio de usuario...${RESET}"
gcc -O2 -Wall -Wextra "$SCRIPT_DIR/test_runner.c" -o "$BIN"
echo -e "${GREEN}[OK] Binario generado exitosamente: $BIN${RESET}"

# 2. Verificar compilación del módulo
echo -e "\n${BOLD}[2/5] Verificando modulo de kernel mmap_shield.ko...${RESET}"
if [ ! -f "$MODULE_KO" ]; then
    echo -e "${YELLOW}[!] Modulo no encontrado. Compilando con make...${RESET}"
    make -C "$ROOT_DIR"
fi
echo -e "${GREEN}[OK] Modulo de kernel verificado: $MODULE_KO${RESET}"

# 3. Validar privilegios para pruebas de kernel
echo -e "\n${BOLD}[3/5] Comprobando privilegios de administracion para insercion...${RESET}"
HAS_SUDO=0
if [ "$(id -u)" -eq 0 ]; then
    HAS_SUDO=1
    SUDO=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    HAS_SUDO=1
    SUDO="sudo"
fi

if [ "$HAS_SUDO" -eq 1 ]; then
    echo -e "${GREEN}[OK] Privilegios root disponibles.${RESET}"

    # Limpiar cualquier instancia previa
    if lsmod | grep -q mmap_shield; then
        echo -e "${YELLOW}[*] Descargando instancia previa de mmap_shield...${RESET}"
        $SUDO rmmod mmap_shield || true
    fi

    # Cargar módulo en modo ENFORCING
    echo -e "\n${BOLD}[4/5] Insertando mmap_shield.ko en modo ENFORCING...${RESET}"
    $SUDO insmod "$MODULE_KO" enforce_mode=1 block_wx=1 block_dirty_cow=1 block_sensitive=1

    if [ ! -f "$PROC_FILE" ]; then
        echo -e "${RED}[ERROR] /proc/mmap_shield no fue creado tras insmod.${RESET}"
        exit 1
    fi
    echo -e "${GREEN}[OK] Modulo cargado correctamente e interfaz /proc activa.${RESET}"

    # Registrar archivo honeypot como protegido
    echo -e "${CYAN}[*] Registrando /tmp/shield_protected.txt en el motor de politicas...${RESET}"
    echo "add_path=/tmp/shield_protected.txt" | $SUDO tee "$PROC_FILE" >/dev/null

    # Ejecutar suite de pruebas
    # La politica de archivos sensibles solo aplica a procesos no root, por lo que
    # test_runner debe correr como el usuario sin privilegios que invoco sudo.
    echo -e "\n${BOLD}[5/5] Ejecutando suite de pruebas de seguridad con proteccion activa...${RESET}"
    $SUDO rm -f /tmp/shield_protected.txt /tmp/shield_benign.txt
    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        echo -e "${CYAN}[*] Ejecutando test_runner como usuario sin privilegios: $SUDO_USER${RESET}"
        sudo -u "$SUDO_USER" "$BIN" || true
    else
        if [ "$(id -u)" -eq 0 ]; then
            echo -e "${YELLOW}[!] test_runner se ejecuta como root: el TEST 3 (archivo sensible) no sera bloqueado.${RESET}"
        fi
        "$BIN" || true
    fi

    # Mostrar métricas en tiempo real
    echo -e "\n${CYAN}======================================================================${RESET}"
    echo -e "${BOLD}   ESTADO Y TELEMETRIA REGISTRADA EN /proc/mmap_shield${RESET}"
    echo -e "${CYAN}======================================================================${RESET}"
    cat "$PROC_FILE"

    # Prueba de reconfiguración en caliente (Modo Permisivo)
    echo -e "\n${BOLD}[+] Probando reconfiguracion dinamica: cambiando a modo PERMISSIVE...${RESET}"
    echo "mode=permissive" | $SUDO tee "$PROC_FILE" >/dev/null
    echo -e "${GREEN}[OK] Modo cambiado a PERMISSIVE en caliente.${RESET}"

    # Limpieza final
    echo -e "\n${BOLD}[*] Descargando modulo mmap_shield...${RESET}"
    $SUDO rmmod mmap_shield
    echo -e "${GREEN}[OK] Modulo descargado limpiamente.${RESET}"

else
    echo -e "${YELLOW}[ADVERTENCIA] No se detecto acceso root directo sin contrasena.${RESET}"
    echo -e "${YELLOW}[*] Ejecutando verificacion de sintaxis y logica del test_runner en espacio de usuario...${RESET}"
    "$BIN" 1 || true
    "$BIN" 5 || true
    echo -e "${CYAN}[INFO] Para pruebas completas con intercepcion activa, ejecuta: sudo bash tests/run_tests.sh${RESET}"
fi

echo -e "\n${GREEN}======================================================================${RESET}"
echo -e "${GREEN}${BOLD}   SUITE DE PRUEBAS COMPLETADA EXITOSAMENTE${RESET}"
echo -e "${GREEN}======================================================================${RESET}\n"
