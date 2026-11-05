# mmap-shield-kernel


## Integrantes
- Juan Esteban Palacio Betancur
- Mateo Montoya Ospina
- Thomas Serna Saldarriaga

---

## 1. Contexto y Planteamiento del Problema

En los sistemas operativos modernos de la familia UNIX/Linux, el acceso convencional a archivos a través de llamadas al sistema como `read()`, `write()`, `pread()` y `pwrite()` involucra transiciones explícitas entre el anillo de usuario (**Ring 3 / CPL=3**) y el anillo de supervisor del kernel (**Ring 0 / CPL=0**). Además, requiere el copiado redundante de páginas de datos entre la memoria caché de páginas del kernel (*Page Cache*) y los buffers de memoria del espacio de usuario.

La llamada al sistema `mmap()` permite proyectar archivos directamente en el espacio de direcciones virtuales de un proceso (`struct vm_area_struct` o VMA), delegando la lectura y escritura a la **MMU (Memory Management Unit)** mediante paginación por demanda (*Page Faults*). Una vez que la entrada en la tabla de páginas (**PTE**) ha sido resuelta (`P=1`), los accesos subsecuentes a memoria ocurren a velocidad de hardware sin conmutación de contexto a Ring 0.

### Desafíos Críticos de Seguridad
1. **Ruptura de la Frontera de Supervisión:** Al acceder a los datos directamente a través de punteros en memoria virtual, las aplicaciones no pasan por los filtros tradicionales de I/O de usuario ni por bibliotecas intermedias (`LD_PRELOAD` es trivialmente evadible).
2. **Manipulación de Banderas de Memoria (W^X):** Inyección de código malicioso mediante asignaciones de memoria que combinan permisos de escritura y ejecución (`PROT_WRITE | PROT_EXEC`), violando el principio *Write XOR Execute*.
3. **Ataques de Condición de Carrera (Dirty COW / CVE-2016-5195):** Explotación de la interacción entre memoria Copy-On-Write (`MAP_PRIVATE`), desprotección de páginas y llamadas como `madvise(MADV_DONTNEED)` para forzar escrituras arbitrarias sobre el *Page Cache* de archivos en disco de solo lectura.
4. **Exposición Cruzada en Memoria Compartida (`MAP_SHARED`):** Procesos no autorizados alterando archivos críticos del sistema en disco a través de proyecciones compartidas.

---

## 2. Arquitectura de `mmap-shield`

`mmap-shield` es un módulo cargable de kernel (**LKM - Loadable Kernel Module**) para x86-64 que intercepta con ftrace dos puntos de la capa LSM del kernel:

- **`security_mmap_file(file, prot, flags)`**: se ejecuta en cada solicitud de mapeo antes de crear el VMA, tanto para archivos como para memoria anónima (`file == NULL`). Cubre `mmap`, `mmap2` y las llamadas de compatibilidad de 32 bits, `remap_file_pages` y `shmat`.
- **`security_file_mprotect(vma, reqprot, prot)`**: se ejecuta en cada cambio de permisos de un VMA existente (`mprotect`, `pkey_mprotect`). Sin este punto, cualquier política aplicada en `mmap` se evade mapeando con permisos inofensivos y cambiándolos después.

```
                                  ESPACIO DE USUARIO (Ring 3)
   +---------------------------------------------------------------------------------------+
   |   Proceso (mmap / mprotect)        test_runner / race_attacks / bench_mmap            |
   +-----------------------------------------+---------------------------------------------+
                                             | syscall
   =================================== FRONTERA RING 0 =====================================
                                    CAPA DE KERNEL (Ring 0)
   +---------------------------------------------------------------------------------------+
   |  vm_mmap_pgoff() -> security_mmap_file()      do_mprotect_pkey() -> security_file_mprotect()
   |                         |  (entrada de la funcion: __fentry__ / ftrace)               |
   |                         v                                                             |
   |  [Motor de Intercepcion - callback ftrace, sin dormir]                                |
   |   - Filtro ftrace por nombre de funcion (ftrace_set_filter)                           |
   |   - Lee argumentos de pt_regs y consulta al motor de politicas                        |
   |   - Si se deniega: regs->ip -> stub del modulo que retorna -EACCES                    |
   |   - Si se permite: no toca nada; el kernel ejecuta la funcion original                |
   +-----------------------------------------+---------------------------------------------+
                                             v
   +---------------------------------------------------------------------------------------+
   |  [Motor de Politicas]  (proteccion efectiva, incluye READ_IMPLIES_EXEC)               |
   |   1. W^X: PROT_WRITE + PROT_EXEC en el mismo mapeo                                    |
   |   2. Alias W^X: vista ejecutable de un archivo con vistas escribibles                 |
   |   3. Precursor Dirty COW: descriptor RO + mapeo privado escribible (archivo protegido)|
   |   4. Archivos sensibles: escritura no root sobre archivos protegidos (inodo o ruta)   |
   |   5. MAP_SHARED escribible con descriptor de solo lectura                             |
   +--------------------+------------------------------------+-----------------------------+
              Permitir  |                                    | Denegar (-EACCES)
                        v                                    v
   +--------------------+-------------+    +-----------------+-----------------------------+
   |  Ejecucion original del kernel   |    |  Telemetria y auditoria                       |
   |  - do_mmap / mprotect_fixup      |    |  - Buffer circular de eventos                 |
   |  - Creacion de VMA y Page Faults |    |  - Interfaz interactiva /proc/mmap_shield     |
   +----------------------------------+    +-----------------------------------------------+
```

### Decisión dentro del callback de ftrace (compatibilidad con IBT)

El callback de ftrace se ejecuta a la entrada de la función interceptada, evalúa la política y, si debe denegar, cambia el puntero de instrucción guardado (`regs->ip`) hacia un *stub* del módulo con la misma firma que solo retorna `-EACCES`. Si se permite, no modifica nada y el kernel ejecuta la función original por sí mismo. Es el mismo mecanismo que usa *livepatch*. El módulo **nunca llama a funciones del kernel a través de punteros**:

- En kernels con **IBT** (Indirect Branch Tracking, `CONFIG_X86_KERNEL_IBT`, activo por ejemplo en WSL2 sobre procesadores Intel recientes), `objtool` elimina la instrucción `ENDBR` de las funciones que solo reciben llamadas directas, como `security_mmap_file` o `kallsyms_lookup_name`, que no se exportan. Una llamada indirecta desde un módulo a esas funciones produce `#CP` (*Missing ENDBR*) y un `BUG()`. Por eso los ganchos se registran por nombre con `ftrace_set_filter()` y no hace falta resolver direcciones con `kallsyms_lookup_name`.
- Como la función original no se ejecuta desde el módulo, no queda ningún marco del módulo en la pila mientras esa función duerme, y el módulo se puede descargar con llamadas en curso.

Este diseño sustituye al gancho sobre la tabla de llamadas al sistema (`__x64_sys_mmap`): desde Linux 6.9 el despacho de syscalls en x86-64 ya no usa `sys_call_table`, y los ganchos LSM cubren todos los puntos de entrada (incluidos los de 32 bits).

---

## 3. Componentes e Implementación Modular

| Archivo | Responsabilidad Arquitectónica |
|---|---|
| `include/mmap_shield.h` | Estructuras maestras de configuración, telemetría atómica (`shield_stats`), buffer circular de auditoría, códigos de veredicto y origen del evento (`mmap` / `mprotect`). |
| `include/hook_engine.h` | Estructura de los ganchos ftrace (función, decisión, stub de denegación) y prototipos del subsistema de intercepción. |
| `include/policy.h` | Registro de archivos protegidos (ruta + inodo) y funciones de evaluación `shield_check_mmap()` / `shield_check_mprotect()`. |
| `include/proc_interface.h` | Prototipos del sistema de archivos virtual `/proc/mmap_shield`. |
| `src/main.c` | Punto de entrada y salida, parámetros de carga (`enforce_mode`, `block_wx`, etc., de solo lectura tras la carga), orquestación del ciclo de vida y buffer circular de auditoría con `spin_lock_irqsave`. |
| `src/hook_engine.c` | Registro de `ftrace_ops` por nombre sobre `security_mmap_file` y `security_file_mprotect`, lectura de argumentos con `regs_get_kernel_argument()` y redirección a los stubs de denegación. |
| `src/policy.c` | Motor de decisiones: protección efectiva (`READ_IMPLIES_EXEC`), alias W^X (`mapping_writably_mapped()`), identificación de archivos por inodo y ruta (`kern_path()`, `file_inode()`, `d_path()` sobre un buffer en pila) y verificación de credenciales (`current_uid()`). Todo apto para contexto atómico. |
| `src/proc_interface.c` | Interfaz administrativa y de telemetría `/proc/mmap_shield` con `seq_file` y `proc_ops`: métricas, rutas protegidas con su inodo, registro de auditoría con origen y comandos de reconfiguración (`mode=permissive`, `add_path=...`, `reset_stats`). |
| `tests/test_runner.c` | Once pruebas de mapeos permitidos, rechazados y evasiones en espacio de usuario. |
| `tests/race_attacks.c` | Simulación de ataques de carrera (Dirty COW con `madvise` + `mprotect` + `/proc/self/mem`, TOCTOU con `renameat2(RENAME_EXCHANGE)`) y carga continua para probar la descarga del módulo. |
| `tests/run_tests.sh` | Suite completa con el módulo cargado: pruebas, verificación de auditoría, uso normal del sistema, carreras, ciclos de descarga/recarga y revisión de `dmesg`. |
| `tests/bench_mmap.c` | Microbenchmark de `mmap`, `mprotect` y fallos de página. |
| `tests/measure_overhead.sh` | Medición del sobrecosto sin y con el módulo con `bench_mmap`, `perf stat`, `strace -c` y ftrace (`function_graph`). |
| `tests/benchmark_mmap.py` | Comparación alternativa en Python del tiempo de `mmap` y de los fallos de página. |
| `results/` | Salidas de la suite y de la medición en el kernel donde se probó. |
| `Makefile` | Compilación del módulo con Kbuild y de las pruebas de usuario. |

---

## 4. Políticas de Seguridad Implementadas

Todas las políticas se aplican tanto a nuevos mapeos (`mmap`) como a cambios de permisos (`mprotect`). En `mmap` se evalúa la **protección efectiva**: con la personalidad `READ_IMPLIES_EXEC`, `do_mmap()` agrega `PROT_EXEC` a un mapeo legible, así que `PROT_READ | PROT_WRITE` termina siendo RWX aunque no se haya pedido. El módulo replica `mmap_prot()` de `security/security.c` para verlo.

### A. Cumplimiento de la Política W^X (Write XOR Execute)
- **Riesgo:** Un atacante proyecta una región de memoria con permisos de escritura y ejecución para cargar código binario (shellcode) y ejecutarlo inmediatamente en el contexto del proceso.
- **Defensa:** Si la protección efectiva incluye `PROT_WRITE` y `PROT_EXEC`, se rechaza con `-EACCES`, ya sea en `mmap` o al pasar de RW a RWX con `mprotect`.

### B. W^X entre alias del mismo archivo
- **Riesgo:** Un archivo (típicamente un `memfd`) se mapea dos veces: una vista para escribir y otra para ejecutar. Ninguna llamada pide W y X a la vez, pero el código escrito por una vista se ejecuta por la otra.
- **Defensa:** Se rechaza `PROT_EXEC` sobre un archivo que tiene mapeos compartidos escribibles (`mapping_writably_mapped()`) o cuando la propia vista es compartida y puede ser escribible (descriptor con `FMODE_WRITE` o VMA con `VM_MAYWRITE`).

### C. Mitigación en Origen de Ataques Dirty COW (CVE-2016-5195)
- **Riesgo:** El atacante abre un archivo de solo lectura (por ejemplo, de root) y obtiene una copia privada escribible (`MAP_PRIVATE` + `PROT_WRITE`). Hilos concurrentes con `madvise(MADV_DONTNEED)` y escrituras en `/proc/self/mem` engañaban al manejador de fallos de página para escribir en el *Page Cache* del archivo real.
- **Defensa:** Sobre archivos protegidos se rechaza la combinación de descriptor de solo lectura (`!(file->f_mode & FMODE_WRITE)`) con mapeo privado escribible, tanto pedido en `mmap` como obtenido después con `mprotect`. La variante clásica mapea con `PROT_READ` y escribe por `/proc/self/mem` (`FOLL_FORCE`); esa ruta no pasa por estos ganchos y su defensa es la corrección del kernel (desde 4.8.3), que la prueba de carrera verifica.

### D. Protección de Archivos Sensibles y del Sistema
- **Riesgo:** Procesos no privilegiados solicitando mapeos escribibles de archivos sensibles como `/etc/shadow`, `/etc/passwd` o `/etc/sudoers`.
- **Defensa:** Si un proceso no root pide `PROT_WRITE` sobre un archivo protegido, se rechaza. Al registrar una ruta se guarda también el inodo al que apunta (`kern_path()`), y un archivo se considera protegido si coincide el **inodo** (cubre enlaces duros, renombrados, montajes *bind* y otros espacios de nombres) **o la ruta** (cubre archivos creados o reemplazados después del registro, como `/etc/passwd` tras `passwd`). Volver a registrar una ruta actualiza su inodo. La ruta se resuelve con `d_path()` sobre un buffer en la pila, sin reservar memoria, así que la comprobación no falla abierta por falta de memoria.

### E. Integridad en Memoria Compartida (`MAP_SHARED`)
- **Riesgo:** Escrituras no autorizadas en archivos subyacentes cuando el descriptor no posee facultades de escritura.
- **Defensa:** Verificación de coherencia entre `file->f_mode & FMODE_WRITE` y un mapeo compartido con `PROT_WRITE`. El gancho se ejecuta antes que `do_mmap()`, por lo que el rechazo queda registrado como `BLOQUEO_SHARED` (el kernel también lo rechazaría sin el módulo).

### Alcance de la protección

- **Cubre:** `mmap`, `mmap2`/compatibilidad de 32 bits, `remap_file_pages`, `shmat`, `mprotect` y `pkey_mprotect`.
- **No cubre:**
  - Cada acceso a una página ya mapeada: los fallos de página no se interceptan.
  - Las escrituras por `/proc/<pid>/mem` o `ptrace` (`FOLL_FORCE`), que dependen de la corrección del kernel.
  - Un alias RX→RW en el que la vista ejecutable se crea primero desde un descriptor de solo lectura y la escribible después desde otro descriptor.
  - Arquitecturas distintas de x86-64.
- **Efectos de la política:** los entornos JIT que usan doble mapeo (por ejemplo, .NET con W^X) quedan bloqueados por diseño; `block_wx=0` desactiva esa política.
- **Inodos reutilizados:** un archivo nuevo que reutilice el inodo de uno protegido y borrado quedaría protegido hasta volver a registrar la ruta.

---

## 5. Compilación y Uso

### Requisitos del Sistema
- Linux x86-64 con soporte de módulos y ftrace con registros (`CONFIG_FTRACE`, `CONFIG_DYNAMIC_FTRACE_WITH_REGS`). No requiere kprobes.
- Cabeceras correspondientes al kernel en ejecución (`linux-headers-$(uname -r)` en Debian/Ubuntu).
- Herramientas: `gcc`, `make`, `bash`, `runuser`; para la medición, opcionalmente `perf` (`linux-tools-generic`) y `strace`; Python 3 para `benchmark_mmap.py`.

### Compatibilidad verificada

| Kernel | Compilación (`make W=1`) | Carga y pruebas |
|---|---|---|
| Ubuntu 5.15.0-203-generic | Sin advertencias | No probado |
| WSL2 6.18.33.2-microsoft-standard-WSL2 (IBT activo) | Sin advertencias | Suite completa y medición (ver `results/`) |
| Ubuntu 7.0.0-38-generic | Sin advertencias | No probado |

### Comandos del Makefile

```bash
# 1. Compilación limpia del módulo de kernel
make

# 2. Compilación de los binarios de prueba en espacio de usuario
make tests

# 3. Opcional: cargar el módulo en el kernel (requiere privilegios sudo)
make load

# 4. Consultar el estado y telemetría en tiempo real
make status

# 5. Descargar el módulo del kernel
make unload

# 6. Ejecutar la suite completa con el módulo inicialmente descargado
sudo make run-tests

# 7. Medir el sobrecosto sin y con el módulo (genera results/overhead-<kernel>.txt)
sudo make measure

# 8. Limpiar todos los artefactos compilados
make clean
```

Para compilar contra las cabeceras de otra versión de kernel, indique su directorio de compilación explícitamente:

```bash
make KDIR=/ruta/a/cabeceras/build
```

Esto permite comprobar la compilación para ese kernel, pero no implica que el módulo resultante pueda cargarse en el kernel actual.

### Prueba en WSL2

WSL2 no publica paquetes de cabeceras para su kernel. Para compilar contra el kernel en ejecución hay que preparar su árbol de fuentes:

```bash
sudo apt-get install -y build-essential flex bison libelf-dev libssl-dev dwarves bc cpio
git clone --depth 1 --branch linux-msft-wsl-$(uname -r | sed 's/-microsoft-standard-WSL2//') \
    https://github.com/microsoft/WSL2-Linux-Kernel.git ~/WSL2-Linux-Kernel
cd ~/WSL2-Linux-Kernel && rm -rf .git && zcat /proc/config.gz > .config && make olddefconfig && make -j"$(nproc)"
cd - && make KDIR=~/WSL2-Linux-Kernel
```

Si el árbol se compila con una versión de gcc distinta de la del kernel de WSL, los CRC de `CONFIG_MODVERSIONS` no coinciden: `insmod` responde `Invalid module format` y `dmesg` muestra `disagrees about version of symbol module_layout`. Con la misma configuración, el módulo puede cargarse forzando la versión (el kernel de WSL tiene `CONFIG_MODULE_FORCE_LOAD`), y el Makefile y los scripts aceptan el comando de carga en la variable `INSMOD`:

```bash
make load INSMOD="insmod -f"
sudo make run-tests INSMOD="insmod -f"
sudo make measure INSMOD="insmod -f"
```

---

## 6. Telemetría y Control Dinámico (`/proc/mmap_shield`)

El módulo exporta una interfaz interactiva en `/proc/mmap_shield` que permite monitorear y reconfigurar la seguridad en tiempo de ejecución sin necesidad de reiniciar el sistema ni descargar el módulo.

### Lectura de Estado y Métricas
```bash
cat /proc/mmap_shield
```
**Salida real tras las pruebas funcionales** (WSL2, kernel 6.18):
```
================================================================================
 [mmap-shield v1.0.0] Monitor de Seguridad de Memoria en Capa de Kernel
================================================================================

Estado del Modulo:        ACTIVO
Modo de Operacion:        [ENFORCING (Bloqueo activo)]
Politica W^X:             [HABILITADO]
Deteccion Dirty COW:      [HABILITADO]
Proteccion Sensibles:     [HABILITADO]
Auditoria Total (Benign): [DESHABILITADO]

--- Metricas y Telemetria en Tiempo Real ---
  Total llamadas interceptadas:     267
    De ellas, cambios mprotect:     45
  Mapeos permitidos:                256
  Mapeos bloqueados:                11
  Violaciones W^X prevenidas:       3
  Alias W^X (doble mapeo) evitados: 2
  Accesos sensibles bloqueados:     3
  Patrones Dirty COW detectados:    2
  Violaciones MAP_SHARED Write:     1

--- Rutas de Archivos Sensibles Protegidos ---
  - /etc/shadow [inodo 56616, dev 8:48]
  - /etc/passwd [inodo 44906, dev 8:48]
  - /etc/sudoers [inodo 1281, dev 8:48]
  - /etc/ld.so.preload [sin inodo: proteccion por ruta]
  - /tmp/shield_protected.txt [sin inodo: proteccion por ruta]
  - /tmp/mmap-shield-test-DuB9nB/protected [inodo 80, dev 0:71]

--- Registro Circular de Auditoria de Seguridad (Ultimos Eventos) ---
TIMESTAMP    PID    TGID   UID    COMANDO          ORIGEN   VERDICTO         ENF  PROT   FLAGS  RUTA
--------------------------------------------------------------------------------------------------------------------------
[1793908695] 6360   6360   1000   test_runner      MMAP     BLOQUEO_W^X      SI   0x0007 0x0022 <anonymous>
[1793908695] 6360   6360   1000   test_runner      MMAP     BLOQUEO_SENS     SI   0x0003 0x0001 /tmp/mmap-shield-test-DuB9nB/protected
[1793908695] 6360   6360   1000   test_runner      MMAP     DIRTY_COW        SI   0x0003 0x0002 /tmp/mmap-shield-test-DuB9nB/protected
[1793908695] 6360   6360   1000   test_runner      MMAP     BLOQUEO_SHARED   SI   0x0003 0x0001 /tmp/mmap-shield-test-DuB9nB/benign
[1793908695] 6360   6360   1000   test_runner      MPROTECT BLOQUEO_W^X      SI   0x0007 0x0002 <anonymous>
[1793908695] 6360   6360   1000   test_runner      MMAP     BLOQUEO_W^X      SI   0x0007 0x0022 <anonymous>
[1793908695] 6360   6360   1000   test_runner      MMAP     BLOQUEO_ALIAS_WX SI   0x0005 0x0001 /memfd:mmap-shield-alias (deleted)
[1793908695] 6360   6360   1000   test_runner      MMAP     BLOQUEO_ALIAS_WX SI   0x0005 0x0001 /memfd:mmap-shield-alias (deleted)
[1793908695] 6360   6360   1000   test_runner      MPROTECT DIRTY_COW        SI   0x0003 0x0002 /tmp/mmap-shield-test-DuB9nB/protected
[1793908695] 6360   6360   1000   test_runner      MMAP     BLOQUEO_SENS     SI   0x0003 0x0001 /tmp/mmap-shield-test-DuB9nB/alias
[1793908695] 6360   6360   1000   test_runner      MPROTECT BLOQUEO_SENS     SI   0x0003 0x0001 /tmp/mmap-shield-test-DuB9nB/protected
================================================================================
```

En la segunda fila `BLOQUEO_W^X` de origen `MMAP` (prueba 7) se pidió `PROT_READ | PROT_WRITE` y se registra la protección efectiva `0x7`.

### Comandos de Reconfiguración en Caliente
```bash
# Cambiar entre modo estricto (bloqueo) y permisivo (solo registrar auditoría)
echo "mode=permissive" | sudo tee /proc/mmap_shield
echo "mode=enforcing"  | sudo tee /proc/mmap_shield

# Activar o desactivar políticas específicas
echo "block_wx=0"          | sudo tee /proc/mmap_shield
echo "block_dirty_cow=1"   | sudo tee /proc/mmap_shield

# Añadir (o refrescar el inodo de) y eliminar rutas de archivos protegidos en caliente
echo "add_path=/mi/archivo/confidencial.db" | sudo tee /proc/mmap_shield
echo "del_path=/mi/archivo/confidencial.db" | sudo tee /proc/mmap_shield

# Reiniciar contadores de métricas y buffer de auditoría
echo "reset_stats" | sudo tee /proc/mmap_shield
```

Las rutas añadidas deben ser absolutas y tener menos de 256 bytes. Los comandos inválidos y los errores al añadir o eliminar rutas se notifican al proceso que escribe. Los parámetros de carga (`enforce_mode`, `block_wx`, ...) son de solo lectura una vez cargado el módulo; los cambios en caliente se hacen por `/proc/mmap_shield`.

---

## 7. Suite de Pruebas

### Pruebas funcionales y de evasión (`tests/test_runner.c`)

| Escenario | Condición Evaluada | Comportamiento Esperado |
|---|---|---|
| **Test 1** | Mapeo legítimo de archivo con `PROT_READ` y `MAP_PRIVATE` | Operación exitosa y datos leídos coinciden |
| **Test 2** | Asignación anónima con `PROT_WRITE \| PROT_EXEC` (violación W^X) | Bloqueado (`BLOQUEO_W^X`) |
| **Test 3** | `MAP_SHARED \| PROT_WRITE` sobre archivo protegido, usuario no root | Bloqueado (`BLOQUEO_SENS`) |
| **Test 4** | Precursor Dirty COW: `O_RDONLY` + `MAP_PRIVATE \| PROT_WRITE` sobre archivo protegido | Bloqueado antes de crear el VMA (`DIRTY_COW`) |
| **Test 5** | Descriptor en solo lectura con `MAP_SHARED \| PROT_WRITE` | Rechazado (`BLOQUEO_SHARED`; sin módulo también lo rechaza el kernel) |
| **Test 6** | Mapeo anónimo RW y luego `mprotect` a RWX | Bloqueado en `mprotect` (`BLOQUEO_W^X`, origen `MPROTECT`) |
| **Test 7** | Personalidad `READ_IMPLIES_EXEC` + `mmap(PROT_READ \| PROT_WRITE)` | Bloqueado por la protección efectiva RWX |
| **Test 8** | `memfd` mapeado RW y RX (antes y después de la vista escribible) | Ambas vistas ejecutables bloqueadas (`BLOQUEO_ALIAS_WX`) |
| **Test 9** | Precursor Dirty COW en dos pasos: `PROT_READ` y luego `mprotect(PROT_WRITE)` | Bloqueado en `mprotect` (`DIRTY_COW`) |
| **Test 10** | Enlace duro al archivo protegido y `MAP_SHARED \| PROT_WRITE` por la nueva ruta | Bloqueado por inodo; contenido intacto |
| **Test 11** | `MAP_SHARED \| PROT_READ` del archivo protegido y luego `mprotect(PROT_WRITE)` | Bloqueado en `mprotect` (`BLOQUEO_SENS`) |

Las pruebas 3, 4, 9, 10 y 11 requieren un usuario sin privilegios y que el archivo esté registrado en el módulo; `run_tests.sh` se encarga de ambas cosas.

### Ataques de carrera (`tests/race_attacks.c`)

| Carrera | Ataque | Resultado esperado |
|---|---|---|
| **Dirty COW** | Sobre un archivo de root (`0644`) mapeado `MAP_PRIVATE \| PROT_READ`: un hilo ejecuta `madvise(MADV_DONTNEED)`, otro intenta `mprotect(PROT_WRITE)` y el principal escribe por `/proc/self/mem` durante 3 s | Ningún `mprotect` concedido y archivo intacto |
| **TOCTOU** | Un hilo intercambia atómicamente los nombres del archivo protegido y de un señuelo (`renameat2(RENAME_EXCHANGE)`) mientras el principal abre el señuelo y lo mapea con escritura compartida | Cero mapeos escribibles del inodo protegido |

### Ejecución (`sudo make run-tests`)

La suite exige que el módulo esté descargado al comenzar y luego:
1. Carga el módulo, registra los archivos de prueba y ejecuta `test_runner` como el usuario que invocó `sudo` (o `nobody`).
2. Comprueba en `/proc/mmap_shield` los eventos de auditoría de cada política y de origen `MPROTECT`.
3. Ejecuta comandos habituales (`ls`, `python3`, `gcc`, `make`, `git`) con el módulo cargado para descartar falsos positivos.
4. Ejecuta las carreras y verifica con `sha256sum` que el archivo de root no cambió.
5. Descarga y recarga el módulo 10 veces mientras otro proceso hace `mmap`/`mprotect` sin parar.
6. Revisa que `dmesg` no tenga `Missing ENDBR`, `BUG`, `Oops` ni trazas de llamada desde el inicio de la suite.

Un fallo produce un código de salida distinto de cero.

---

## 8. Medición de rendimiento y fallos de página

`sudo make measure` ejecuta `tests/measure_overhead.sh`, que repite el mismo trabajo sin y con el módulo cargado y guarda la salida en `results/overhead-<kernel>.txt`:

- **`bench_mmap`** (mediana y rango de `REPS` rondas): ns por `mmap`+`munmap` de archivo (`PROT_READ` y `PROT_READ|PROT_WRITE`) y anónimo, ns por `mprotect` (anónimo y de archivo) y ns por fallo de página.
- **ftrace `function_graph`** (mediana y rango de `REPS` rondas): latencia media dentro del kernel de `__x64_sys_mmap`, `__x64_sys_mprotect` y `handle_mm_fault`, filtrando las líneas del proceso de prueba. El trazador solo está activo durante su propia ejecución, así que no afecta las de `bench_mmap`.
- **`perf stat`**: fallos de página, cambios de contexto y tiempo de CPU.
- **`strace -c`**: tiempo medio por llamada de `mmap`, `mprotect` y `munmap` (con el sobrecosto propio de `strace`).

Las rondas de `bench_mmap` y ftrace se intercalan en orden ABBA: en las impares se mide sin módulo, se carga y se mide con módulo; en las pares, con módulo, se descarga y sin módulo. En un procesador híbrido como el Core Ultra 9 275HX, una misma ejecución puede caer en un núcleo P o E y variar 2 a 3 veces; al intercalar, esa variación afecta por igual a ambos casos y la mediana la filtra, y cada caso queda la mitad de las veces justo después de cargar o descargar el módulo. `strace` se fija a una CPU con `taskset` (`STRACE_CPU`, por defecto 0), porque si el trazador y el proceso trazado quedan en CPUs distintas el coste de despertarse entre ellas (unos 20 µs) tapa el de la llamada. Para los fallos de página, `bench_mmap` alinea el mapeo a la ventana de *fault-around* (64 KB, 16 páginas): con la dirección que elige ASLR, un mapeo de 64 páginas produce 4 o 5 fallos según su alineación, y con ello cambia el costo por fallo. Alineado, siempre son 4.

Las variables `ITERATIONS` (20000), `PAGES` (64), `REPS` (10) y `STRACE_CPU` (0) permiten cambiar la carga. `tests/benchmark_mmap.py` ofrece una comparación alternativa en Python:

```bash
python3 tests/benchmark_mmap.py baseline mmap-baseline.json   # sin el módulo
make load
python3 tests/benchmark_mmap.py compare mmap-baseline.json    # con el módulo
make unload
```

---

## 9. Resultados

Ejecutados en WSL2 (kernel 6.18.33.2-microsoft-standard-WSL2, IBT activo, Intel Core Ultra 9 275HX). El módulo se cargó con `insmod -f` por la diferencia de compilador descrita en la sección 5. Salidas completas en `results/`.

### Pruebas (`results/tests-6.18.33.2-microsoft-standard-WSL2.txt`)

- Pruebas funcionales y de evasión: **11 de 11** superadas.
- Uso normal del sistema con el módulo cargado: `ls`, `bash`, `python3`, `gcc`, `make` y `git` funcionan sin bloqueos.
- Carrera Dirty COW: 2 902 995 llamadas a `madvise`, 41 849 intentos de `mprotect(PROT_WRITE)` (0 concedidos) y 161 189 escrituras por `/proc/self/mem` (solo afectan la copia privada); archivo de root intacto.
- Carrera TOCTOU: 1 187 435 intercambios de nombre; el inodo protegido se abrió 205 202 veces bajo el nombre del señuelo y se obtuvieron 0 mapeos escribibles sobre él.
- 10 ciclos de descarga y recarga del módulo mientras otro proceso completaba 568 776 iteraciones de `mmap`/`mprotect`/`munmap`, sin errores en `dmesg` (`results/dmesg-6.18.33.2-microsoft-standard-WSL2.txt`).

### Sobrecosto (`results/overhead-6.18.33.2-microsoft-standard-WSL2.txt`)

`bench_mmap`, mediana de 5 ejecuciones de 20 000 iteraciones sobre 64 páginas:

| Métrica | Sin módulo | Con módulo | Cambio |
|---|---:|---:|---:|
| `mmap`+`munmap` archivo, `PROT_READ` (ns) | 3002.7 | 3103.8 | +3.4 % |
| `mmap`+`munmap` archivo, `PROT_READ\|PROT_WRITE` (ns) | 3120.3 | 3528.4 | +13.1 % |
| `mmap`+`munmap` anónimo (ns) | 3275.6 | 3448.4 | +5.3 % |
| `mprotect` anónimo (ns) | 1446.6 | 1597.0 | +10.4 % |
| `mprotect` de archivo (ns) | 834.4 | 1020.1 | +22.3 % |
| Fallo de página (ns) | 3101.6 | 3089.8 | −0.4 % |
| Fallos por mapeo de 64 páginas | 5.00 | 5.00 | 0 % |

ftrace `function_graph`, latencia media dentro del kernel con 1000 iteraciones (medida con el trazador activo, que añade su propio costo):

| Función | Llamadas | Sin módulo (µs) | Con módulo (µs) | Cambio |
|---|---:|---:|---:|---:|
| `__x64_sys_mmap` | 3063 | 1.919 | 1.822 | −5.1 % |
| `__x64_sys_mprotect` | 4003 | 0.442 | 1.395 | +215.6 % |
| `handle_mm_fault` | ~390 | 2.357 | 2.404 | +2.0 % |

`perf stat` (5 ejecuciones): 4734 fallos de página sin módulo y 5135 con módulo, todos menores, y 293.74 ms frente a 334.62 ms de CPU. `strace -c`: 22-25 µs por llamada en ambos casos, valor dominado por el propio `strace`. El módulo interceptó 1 426 516 llamadas durante la medición, sin bloquear ninguna.
