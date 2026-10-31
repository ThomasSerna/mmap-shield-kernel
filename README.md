# mmap-shield-kernel 🛡️
> **Módulo de Seguridad en la Capa del Kernel para Intercepción y Protección de Mapeos de Memoria (`mmap` / `file_mmap`)**  
> *Universidad EAFIT — Departamento de Informática y Analítica*  
> *Asignatura: Sistemas Operativos (Periodo 2026-2)*

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

`mmap-shield` es un módulo cargable de kernel (**LKM - Loadable Kernel Module**) diseñado y desarrollado bajo una arquitectura modular y compatible con versiones modernas del kernel Linux (**5.x / 6.x / 7.x**).

```
                                  ESPACIO DE USUARIO (Ring 3)
   +---------------------------------------------------------------------------------------+
   |   Proceso de Usuario (mmap)             Binario de Pruebas (test_runner)              |
   +-----------------------------------------+---------------------------------------------+
                                             | sys_mmap()
                                             v
   =================================== FRONTERA RING 0 =====================================
                                    CAPA DE KERNEL (Ring 0)
   +---------------------------------------------------------------------------------------+
   |  [Motor de Intercepción Hook Engine]                                                  |
   |   - Resolución segura de símbolos no exportados (kallsyms_lookup_name via kprobe)     |
   |   - Hook ftrace en LSM: security_mmap_file (file_mmap)                                |
   |   - Hook ftrace en Syscall: __x64_sys_mmap                                            |
   +-----------------------------------------+---------------------------------------------+
                                             |
                                             v
   +---------------------------------------------------------------------------------------+
   |  [Motor de Políticas de Seguridad Policy Engine]                                      |
   |   1. Validación W^X: Detección y bloqueo de PROT_WRITE | PROT_EXEC                    |
   |   2. Detección Precursora Dirty COW: Bloqueo de RO + MAP_PRIVATE|PROT_WRITE            |
   |   3. Archivos Sensibles: Protección estricta de /etc/shadow, /etc/passwd, etc.        |
   |   4. MAP_SHARED Write Integrity: Validación de descriptores y permisos de escritura   |
   +--------------------+------------------------------------+-----------------------------+
                        |                                    |
            Permitir    |                                    | Denegar (-EACCES / -EPERM)
                        v                                    v
   +--------------------+-------------+    +-----------------+-----------------------------+
   |  Ejecución Original del Kernel   |    |  Registro de Telemetría y Auditoría           |
   |  - vm_mmap_pgoff / do_mmap       |    |  - Buffer circular de eventos                 |
   |  - Creación de VMA y Page Faults |    |  - Interfaz interactiva /proc/mmap_shield     |
   +----------------------------------+    +-----------------------------------------------+
```

---

## 3. Componentes e Implementación Modular

El proyecto está debidamente estructurado en submódulos especializados en lenguaje C:

| Archivo | Responsabilidad Arquitectónica |
|---|---|
| `include/mmap_shield.h` | Estructuras maestras de configuración, telemetría atómica (`shield_stats`), buffer circular de auditoría y constantes globales. |
| `include/hook_engine.h` | Definición de estructuras de ganchos ftrace y prototipos del subsistema de intercepción. |
| `include/policy.h` | Reglas de validación de seguridad (W^X, archivos sensibles, mitigación Dirty COW, integridad compartida). |
| `include/proc_interface.h` | Prototipos del sistema de archivos virtual `/proc/mmap_shield`. |
| `src/main.c` | Punto de entrada (`init_module`) y salida (`cleanup_module`), parámetros del módulo (`enforce_mode`, `block_wx`, etc.), orquestación del ciclo de vida y gestión del buffer circular de auditoría con cerrojos de interrupción (`spin_lock_irqsave`). |
| `src/hook_engine.c` | **Resolución dinámica y segura de símbolos** mediante sondeo temporal con `kprobe` (evitando alucinaciones de código que vulneran el bit WP de CR0 o asumen `kallsyms_lookup_name` exportado en kernels >= 5.7). Enganches concurrentes y libres de recursión per-CPU usando `ftrace_ops` sobre `security_mmap_file` (hook oficial LSM `file_mmap`) y `__x64_sys_mmap`. |
| `src/policy.c` | Motor de toma de decisiones de seguridad: resolución de rutas de archivo con `d_path()`, verificación de credenciales (`current_uid()`), análisis de banderas `prot` y `flags`, y aplicación de políticas en caliente. |
| `src/proc_interface.c` | Interfaz administrativa y de telemetría `/proc/mmap_shield` utilizando el subsistema `seq_file` y `proc_ops`. Provee monitoreo de métricas atómicas en tiempo real, volcado del log de auditoría y recepción de comandos de reconfiguración dinámica (`mode=permissive`, `add_path=...`, `reset_stats`). |
| `tests/test_runner.c` | Suite de pruebas en espacio de usuario que evalúa rigurosamente 5 escenarios de validación de memoria. |
| `tests/run_tests.sh` | Script bash automatizado para compilación, despliegue, ejecución de pruebas de intrusión y auditoría. |
| `Makefile` | Script de compilación limpia para el sistema Kbuild del kernel Linux, libre de advertencias (`-Wall -Wextra`). |

---

## 4. Políticas de Seguridad Implementadas

### A. Cumplimiento de la Política W^X (Write XOR Execute)
- **Riesgo:** Un atacante proyecta una región de memoria con permisos de escritura y ejecución para cargar código binario (shellcode) y ejecutarlo inmediatamente en el contexto del proceso (técnica común en explotación de software y corrupción de memoria).
- **Defensa:** `mmap-shield` inspecciona los argumentos de protección tanto a nivel de llamada al sistema (`__x64_sys_mmap`) como en el hook LSM. Si se detecta `(prot & PROT_WRITE) && (prot & PROT_EXEC)`, la llamada es abortada con error `-EPERM` o `-EACCES`.

### B. Mitigación en Origen de Ataques Dirty COW (CVE-2016-5195)
- **Riesgo:** El atacante abre un archivo de solo lectura del sistema (ej. perteneciente a root) y solicita un mapeo `MAP_PRIVATE | PROT_WRITE`. Aunque POSIX permite esto bajo la semántica Copy-On-Write, hilos concurrentes que ejecutan `madvise(MADV_DONTNEED)` mientras escriben en `/proc/self/mem` engañan al manejador de fallos de página (`handle_mm_fault`) para escribir directamente en el Page Cache del archivo real.
- **Defensa:** `mmap-shield` intercepta `security_mmap_file` y detecta la combinación precursora de este vector: archivo sin permiso de apertura para escritura (`!(file->f_mode & FMODE_WRITE)`) solicitado con `MAP_PRIVATE | PROT_WRITE` sobre archivos protegidos o pertenecientes al sistema. Al bloquear esta llamada, se extirpa la vulnerabilidad antes de que el VMA sea creado.

### C. Protección de Archivos Sensibles y del Sistema
- **Riesgo:** Procesos no privilegiados mapeando archivos críticos como `/etc/shadow`, `/etc/passwd`, `/etc/sudoers` o bibliotecas del sistema para inspección no autorizada o alteración de datos.
- **Defensa:** Mantiene un registro dinámico de rutas protegidas. Si un proceso no root (`current_uid() != 0`) intenta mapear un archivo sensible con privilegios de escritura (`PROT_WRITE` o `MAP_SHARED`), la operación es bloqueada inmediatamente.

### D. Integridad en Memoria Compartida (`MAP_SHARED`)
- **Riesgo:** Escrituras no autorizadas en archivos subyacentes cuando el descriptor no posee facultades de escritura.
- **Defensa:** Verificación estricta de coherencia entre `file->f_mode & FMODE_WRITE` y `(flags & MAP_SHARED) && (prot & PROT_WRITE)`.

---

## 5. Compilación y Uso

### Requisitos del Sistema
- Linux Kernel 5.x, 6.x o 7.x (incluyendo entornos Ubuntu, Debian, Fedora, Arch y WSL2 con soporte de módulos).
- Cabeceras de compilación del kernel instaladas (`linux-headers-$(uname -r)` o `linux-headers-generic`).
- Herramientas de compilación: `gcc`, `make`, `build-essential`.

### Comandos del Makefile

```bash
# 1. Compilación limpia del módulo de kernel
make

# 2. Compilación del binario de pruebas en espacio de usuario
make tests

# 3. Cargar el módulo en el kernel (requiere privilegios sudo)
make load

# 4. Consultar el estado y telemetría en tiempo real
make status

# 5. Ejecutar la suite automatizada de pruebas y validación
make run-tests

# 6. Descargar el módulo del kernel
make unload

# 7. Limpiar todos los artefactos compilados
make clean
```

---

## 6. Telemetría y Control Dinámico (`/proc/mmap_shield`)

El módulo exporta una interfaz interactiva en `/proc/mmap_shield` que permite monitorear y reconfigurar la seguridad en tiempo de ejecución sin necesidad de reiniciar el sistema ni descargar el módulo.

### Lectura de Estado y Métricas
```bash
cat /proc/mmap_shield
```
**Ejemplo de salida:**
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
  Total llamadas interceptadas:     142
  Mapeos permitidos:                138
  Mapeos bloqueados:                4
  Violaciones W^X prevenidas:       1
  Accesos sensibles bloqueados:     1
  Patrones Dirty COW detectados:    1
  Violaciones MAP_SHARED Write:     1

--- Rutas de Archivos Sensibles Protegidos ---
  - /etc/shadow
  - /etc/passwd
  - /etc/sudoers
  - /etc/ld.so.preload
  - /tmp/shield_protected.txt

--- Registro Circular de Auditoria de Seguridad (Ultimos Eventos) ---
TIMESTAMP    PID    TGID   UID    COMANDO          VERDICTO        ENF  PROT   FLAGS  RUTA
----------------------------------------------------------------------------------------------------------------
[1761954200] 8140   8140   1000   test_runner      BLOQUEO_W^X     SI   0x0007 0x0022 <anonymous>
[1761954201] 8140   8140   1000   test_runner      BLOQUEO_SENS    SI   0x0003 0x0001 /tmp/shield_protected.txt
[1761954202] 8140   8140   1000   test_runner      DIRTY_COW       SI   0x0003 0x0002 /tmp/shield_protected.txt
================================================================================
```

### Comandos de Reconfiguración en Caliente
```bash
# Cambiar entre modo estricto (bloqueo) y permisivo (solo registrar auditoría)
echo "mode=permissive" | sudo tee /proc/mmap_shield
echo "mode=enforcing"  | sudo tee /proc/mmap_shield

# Activar o desactivar políticas específicas
echo "block_wx=0"          | sudo tee /proc/mmap_shield
echo "block_dirty_cow=1"   | sudo tee /proc/mmap_shield

# Añadir o eliminar rutas de archivos protegidos en caliente
echo "add_path=/mi/archivo/confidencial.db" | sudo tee /proc/mmap_shield
echo "del_path=/mi/archivo/confidencial.db" | sudo tee /proc/mmap_shield

# Reiniciar contadores de métricas y buffer de auditoría
echo "reset_stats" | sudo tee /proc/mmap_shield
```

---

## 7. Suite de Pruebas y Resultados

El archivo `tests/test_runner.c` implementa pruebas reproducibles para cada vector de seguridad:

| Escenario | Condición Evaluada | Comportamiento Esperado | Resultado |
|---|---|---|---|
| **Test 1** | Mapeo legítimo de archivo con `PROT_READ` y `MAP_PRIVATE` | Operación exitosa, datos leídos coinciden | **PASÓ (PERMITIDO)** |
| **Test 2** | Asignación con `PROT_WRITE \| PROT_EXEC` (Violación W^X) | Bloqueado con `-EPERM` / `-EACCES` | **PASÓ (BLOQUEADO)** |
| **Test 3** | Escritura sobre archivo sensible registrado en la política | Bloqueado con `-EACCES` | **PASÓ (BLOQUEADO)** |
| **Test 4** | Precursor Dirty COW (`O_RDONLY` + `MAP_PRIVATE \| PROT_WRITE`) | Bloqueado preventivamente antes de VMA | **PASÓ (BLOQUEADO)** |
| **Test 5** | Descriptor en solo lectura con `MAP_SHARED \| PROT_WRITE` | Rechazado con `-EACCES` | **PASÓ (RECHAZADO)** |

---

## 8. Licencia
Este proyecto está publicado bajo la licencia **GPL-2.0-only**, de conformidad con los estándares de desarrollo del núcleo de Linux.
