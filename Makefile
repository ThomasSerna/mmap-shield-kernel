# ==============================================================================
# Makefile para el Módulo de Kernel mmap-shield
# Asignatura: Sistemas Operativos (EAFIT) - Periodo 2026-2
# Compatible con Linux Kernel 5.x / 6.x / 7.x
# ==============================================================================

MODULE_NAME := mmap_shield

# Objetos que componen el módulo
obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-y := src/main.o src/hook_engine.o src/policy.o src/proc_interface.o

# Flags de compilación limpia y cabeceras
ccflags-y += -I$(src)/include -Wall

KDIR ?= /lib/modules/$(shell uname -r)/build

PWD := $(CURDIR)

.PHONY: all modules clean load unload reload status tests run-tests help

all: modules

modules:
	@test -d "$(KDIR)" || { echo "No se encontraron cabeceras en $(KDIR). Instale las del kernel activo o indique KDIR." >&2; exit 1; }
	@echo "==> Compilando modulo $(MODULE_NAME) contra $(KDIR)..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	@echo "==> Compilacion exitosa de $(MODULE_NAME).ko"

clean:
	@echo "==> Limpiando artefactos de compilacion del kernel..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@rm -f src/*.o src/.*.cmd src/*.mod src/*.mod.c src/.*.d
	@rm -f tests/test_runner tests/race_attacks tests/*.log
	@echo "==> Limpieza completada."

load:
	@echo "==> Cargando modulo $(MODULE_NAME).ko..."
	@if lsmod | grep -q $(MODULE_NAME); then \
		echo "El modulo $(MODULE_NAME) ya esta cargado."; \
	else \
		sudo insmod $(MODULE_NAME).ko enforce_mode=1 block_wx=1 block_dirty_cow=1 && \
		echo "Modulo $(MODULE_NAME) cargado correctamente."; \
	fi

unload:
	@echo "==> Descargando modulo $(MODULE_NAME)..."
	@if lsmod | grep -q $(MODULE_NAME); then \
		sudo rmmod $(MODULE_NAME) && echo "Modulo descargado."; \
	else \
		echo "El modulo $(MODULE_NAME) no esta cargado."; \
	fi

reload: unload load

status:
	@echo "=== Estado del modulo en /proc/mmap_shield ==="
	@if [ -f /proc/mmap_shield ]; then \
		cat /proc/mmap_shield; \
	else \
		echo "/proc/mmap_shield no existe (el modulo no esta cargado)."; \
	fi
	@echo "\n=== Ultimos registros de dmesg ==="
	@sudo dmesg | grep -E "mmap_shield|mmap" | tail -n 20 || true

tests:
	@echo "==> Compilando suite de pruebas de espacio de usuario..."
	gcc -O2 -Wall -Wextra tests/test_runner.c -o tests/test_runner
	gcc -O2 -Wall -Wextra -pthread tests/race_attacks.c -o tests/race_attacks
	@echo "==> Binarios de pruebas generados: tests/test_runner tests/race_attacks"

run-tests: tests
	@echo "==> Ejecutando suite de pruebas automatizadas..."
	@bash tests/run_tests.sh

help:
	@echo "Opciones disponibles en el Makefile de mmap-shield:"
	@echo "  make              - Compilar el modulo del kernel ($(MODULE_NAME).ko)"
	@echo "  make clean        - Limpiar todos los archivos compilados"
	@echo "  make load         - Cargar el modulo con insmod (requiere sudo)"
	@echo "  make unload       - Descargar el modulo con rmmod (requiere sudo)"
	@echo "  make reload       - Descargar y volver a cargar el modulo"
	@echo "  make status       - Ver telemetria de /proc/mmap_shield y dmesg"
	@echo "  make tests        - Compilar el binario de pruebas en espacio de usuario"
	@echo "  make run-tests    - Ejecutar suite de validacion y pruebas"
