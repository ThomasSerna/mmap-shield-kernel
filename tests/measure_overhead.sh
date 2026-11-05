#!/usr/bin/env bash
# Mide el sobrecosto de mmap-shield comparando el mismo trabajo sin y con el
# modulo cargado:
#   - tests/bench_mmap: coste por llamada medido en espacio de usuario
#   - ftrace:           latencia en kernel de mmap, mprotect y handle_mm_fault (function_graph)
#   - perf stat:        fallos de pagina y cambios de contexto (si perf esta disponible)
#   - strace -c:        tiempo por llamada al sistema (si strace esta disponible)
# bench_mmap y ftrace se ejecutan en rondas intercaladas en orden ABBA (sin y
# con modulo en las rondas impares, con y sin en las pares) y se reporta la
# mediana: asi los cambios de frecuencia o de tipo de nucleo (P/E) del equipo
# afectan por igual a ambos casos, y cada caso queda la mitad de las veces
# justo despues de cargar o descargar el modulo. strace se fija a una CPU para
# que el trazador y el proceso trazado no se despierten entre CPUs, coste que
# domina su medicion.
# El resultado se guarda en results/overhead-<kernel>.txt.
# Variables opcionales: ITERATIONS (20000), PAGES (64), REPS (10), STRACE_CPU (0).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ITERATIONS=${ITERATIONS:-20000}
PAGES=${PAGES:-64}
REPS=${REPS:-10}
STRACE_CPU=${STRACE_CPU:-0}
FTRACE_ITERATIONS=$((ITERATIONS / 20))
BENCH="$SCRIPT_DIR/bench_mmap"
MODULE_KO="$ROOT_DIR/mmap_shield.ko"
METRICS=(mmap_munmap_file_r_ns mmap_munmap_file_rw_ns mmap_munmap_anon_ns
         mprotect_anon_ns mprotect_file_ns page_fault_ns faults_per_mapping)
FTRACE_FUNCS=(__x64_sys_mmap __x64_sys_mprotect handle_mm_fault)
# Loader command; e.g. INSMOD="insmod -f" when the build tree used another compiler (see README)
INSMOD=${INSMOD:-insmod}

if [[ $(id -u) -ne 0 ]]; then
    echo "Ejecute la medicion como root: sudo bash tests/measure_overhead.sh" >&2
    exit 1
fi
if [[ -d /sys/module/mmap_shield ]]; then
    echo "El modulo ya esta cargado; descarguelo antes de medir." >&2
    exit 1
fi

make -C "$ROOT_DIR" tests >/dev/null
if [[ ! -f "$MODULE_KO" ]]; then
    make -C "$ROOT_DIR"
fi

# Ubuntu's /usr/bin/perf wrapper only works with the tools of the running
# kernel; fall back to any installed perf binary.
PERF=""
if command -v perf >/dev/null 2>&1 && perf --version >/dev/null 2>&1; then
    PERF=perf
else
    for candidate in /usr/lib/linux-tools/*/perf /usr/lib/linux-tools-*/perf; do
        [[ -x "$candidate" ]] && PERF="$candidate"
    done
fi
STRACE=$(command -v strace || true)
PIN=()
command -v taskset >/dev/null 2>&1 && PIN=(taskset -c "$STRACE_CPU")
TRACEFS=/sys/kernel/tracing
[[ -e "$TRACEFS/current_tracer" ]] || TRACEFS=/sys/kernel/debug/tracing

mkdir -p "$ROOT_DIR/results"
OUT="$ROOT_DIR/results/overhead-$(uname -r).txt"
TMP=$(mktemp -d)
loaded=0
FTRACE_FILTER=()
FTRACE_OLD_KB=""
FTRACE_LOST=0

ftrace_reset() {
    [[ -e "$TRACEFS/current_tracer" ]] || return 0
    echo 0 > "$TRACEFS/tracing_on"
    echo nop > "$TRACEFS/current_tracer"
    echo > "$TRACEFS/set_ftrace_filter"
    echo > "$TRACEFS/set_ftrace_pid"
    echo > "$TRACEFS/trace"
}

cleanup() {
    local status=$?
    ftrace_reset || true
    if [[ -n "$FTRACE_OLD_KB" ]]; then
        echo "$FTRACE_OLD_KB" > "$TRACEFS/buffer_size_kb" || true
    fi
    if [[ $loaded -eq 1 ]]; then
        rmmod mmap_shield || status=1
    fi
    rm -rf -- "$TMP"
    exit "$status"
}
trap cleanup EXIT

exec > >(tee "$OUT") 2>&1

load_module() {
    $INSMOD "$MODULE_KO"
    loaded=1
}

unload_module() {
    rmmod mmap_shield
    loaded=0
}

median_of() {  # $1 = archivo "clave valor", $2 = clave
    awk -v m="$2" '$1 == m { print $2 }' "$1" | sort -g |
        awk '{ v[NR] = $1 } END { if (NR == 0) print "n/a"; else if (NR % 2) print v[(NR + 1) / 2];
                                  else printf "%.3f\n", (v[NR / 2] + v[NR / 2 + 1]) / 2 }'
}

range_of() {  # $1 = archivo "clave valor", $2 = clave -> "min-max"
    awk -v m="$2" '$1 == m { print $2 }' "$1" | sort -g |
        awk '{ v[NR] = $1 } END { if (NR == 0) print "n/a"; else print v[1] "-" v[NR] }'
}

# Selects the functions that ftrace can trace and enlarges the ring buffer so
# that no event of a run is lost.
ftrace_setup() {
    local f
    if [[ ! -e "$TRACEFS/current_tracer" ]] || ! grep -qw function_graph "$TRACEFS/available_tracers"; then
        return 0
    fi
    for f in "${FTRACE_FUNCS[@]}"; do
        if awk -v f="$f" '$1 == f { found = 1; exit } END { exit !found }' "$TRACEFS/available_filter_functions"; then
            FTRACE_FILTER+=("$f")
        fi
    done
    [[ ${#FTRACE_FILTER[@]} -gt 0 ]] || return 0
    ftrace_reset
    FTRACE_OLD_KB=$(awk '{ print $1; exit }' "$TRACEFS/buffer_size_kb")
    echo 8192 > "$TRACEFS/buffer_size_kb"
}

# One traced run of bench_mmap. function_graph with the filter limited to a few
# functions prints each call as a leaf with its total duration (including
# everything it calls). Every task is traced and the lines of the benchmark are
# selected by process name (funcgraph-proc). The tracer is removed afterwards so
# it does not slow down the untraced runs. Appends "function mean_us calls" to
# $TMP/<prefix>.ftrace.
ftrace_run() {  # $1 = prefijo
    local lost
    [[ ${#FTRACE_FILTER[@]} -gt 0 ]] || return 0
    printf '%s\n' "${FTRACE_FILTER[@]}" > "$TRACEFS/set_ftrace_filter"
    echo function_graph > "$TRACEFS/current_tracer"
    echo 1 > "$TRACEFS/options/funcgraph-proc"
    echo > "$TRACEFS/trace"
    echo 1 > "$TRACEFS/tracing_on"
    "$BENCH" "$FTRACE_ITERATIONS" "$PAGES" > /dev/null
    echo 0 > "$TRACEFS/tracing_on"
    lost=$(cat "$TRACEFS"/per_cpu/cpu*/stats | awk '/^(overrun|dropped events):/ { s += $NF } END { print s + 0 }')
    FTRACE_LOST=$((FTRACE_LOST + lost))
    # Line format: " CPU)  comm-pid  |  duration us  |  function();"
    awk -F'|' 'index($0, "bench_m") && index($0, "();") {
                   d = ""; f = ""
                   for (i = 1; i <= NF; i++) {
                       if (index($i, " us")) d = $i
                       if (index($i, "();")) f = $i
                   }
                   if (d == "" || f == "") next
                   gsub(/[^0-9.]/, "", d); gsub(/[ ();]/, "", f)
                   sum[f] += d; n[f]++
               }
               END { for (f in n) printf "%s %.3f %d\n", f, sum[f] / n[f], n[f] }' \
        "$TRACEFS/trace" >> "$TMP/$1.ftrace"
    echo 0 > "$TRACEFS/options/funcgraph-proc"
    ftrace_reset
}

# Medians of the interleaved rounds plus perf stat and strace for the current
# state of the module.
report() {  # $1 = etiqueta, $2 = prefijo
    local m f calls
    echo
    echo "################ $1 ################"
    echo "--- bench_mmap: mediana de $REPS rondas intercaladas ($ITERATIONS iteraciones, $PAGES paginas) ---"
    for m in "${METRICS[@]}"; do
        printf '  %-26s %-10s (rango %s)\n' "$m" "$(median_of "$TMP/$2.bench" "$m")" "$(range_of "$TMP/$2.bench" "$m")"
    done

    echo "--- ftrace function_graph: latencia en kernel, mediana de $REPS rondas ($FTRACE_ITERATIONS iteraciones c/u) ---"
    if [[ -s "$TMP/$2.ftrace" ]]; then
        for f in "${FTRACE_FILTER[@]}"; do
            calls=$(awk -v f="$f" '$1 == f { print $3 }' "$TMP/$2.ftrace" | sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }')
            printf '  %-22s llamadas=%-8s media_us=%-8s (rango %s)\n' "$f" "$calls" \
                "$(median_of "$TMP/$2.ftrace" "$f")" "$(range_of "$TMP/$2.ftrace" "$f")"
        done
    else
        echo "  (ftrace function_graph no disponible)"
    fi

    echo "--- perf stat ---"
    if [[ -n "$PERF" ]]; then
        "$PERF" stat -e page-faults,minor-faults,major-faults,context-switches,task-clock -r "$REPS" \
            -- "$BENCH" "$ITERATIONS" "$PAGES" 2>&1 >/dev/null | sed -n '/Performance counter/,$p' ||
            echo "  (perf stat fallo)"
    else
        echo "  (perf no disponible)"
    fi

    echo "--- strace -c (mmap, mprotect, munmap; $FTRACE_ITERATIONS iteraciones${PIN:+; fijado a la CPU $STRACE_CPU}) ---"
    if [[ -n "$STRACE" ]]; then
        if "${PIN[@]}" "$STRACE" -c -e trace=mmap,mprotect,munmap -o "$TMP/$2.strace" \
            "$BENCH" "$FTRACE_ITERATIONS" "$PAGES" > /dev/null; then
            cat "$TMP/$2.strace"
        else
            echo "  (strace fallo)"
        fi
    else
        echo "  (strace no disponible)"
    fi
}

echo "mmap-shield: medicion de sobrecosto"
echo "Fecha:       $(date -Iseconds)"
echo "Kernel:      $(uname -r)"
echo "CPU:         $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
echo "Parametros:  ITERATIONS=$ITERATIONS PAGES=$PAGES REPS=$REPS STRACE_CPU=$STRACE_CPU"
echo "Herramientas: perf=${PERF:-no} strace=${STRACE:-no} ftrace=$TRACEFS"

ftrace_setup
echo
echo "################ RONDAS INTERCALADAS ABBA (bench_mmap + ftrace) ################"
measure_once() {  # $1 = prefijo
    "$BENCH" "$ITERATIONS" "$PAGES" >> "$TMP/$1.bench"
    ftrace_run "$1"
}
for r in $(seq 1 "$REPS"); do
    if (( r % 2 )); then
        measure_once base
        load_module
        measure_once shield
        echo "  ronda $r/$REPS: sin modulo, luego con modulo"
    else
        measure_once shield
        unload_module
        measure_once base
        echo "  ronda $r/$REPS: con modulo, luego sin modulo"
    fi
done
[[ $loaded -eq 0 ]] || unload_module
[[ ${#FTRACE_FILTER[@]} -eq 0 ]] || echo "  (eventos de ftrace perdidos por desbordamiento del buffer: $FTRACE_LOST)"

report "SIN MODULO" base

load_module
report "CON MODULO (enforcing, todas las politicas)" shield
echo "--- Telemetria del modulo durante perf y strace ---"
grep -E "interceptadas|mprotect:|permitidos|bloqueados" /proc/mmap_shield
unload_module

echo
echo "################ RESUMEN (medianas de las rondas intercaladas) ################"
printf '  %-26s %12s %12s %10s\n' "METRICA" "SIN_MODULO" "CON_MODULO" "CAMBIO"
for m in "${METRICS[@]}"; do
    base=$(median_of "$TMP/base.bench" "$m")
    shield=$(median_of "$TMP/shield.bench" "$m")
    awk -v m="$m" -v a="$base" -v b="$shield" 'BEGIN {
        c = (a + 0 != 0) ? sprintf("%+.1f%%", (b - a) * 100 / a) : "n/a"
        printf "  %-26s %12s %12s %10s\n", m, a, b, c }'
done
if [[ -s "$TMP/base.ftrace" && -s "$TMP/shield.ftrace" ]]; then
    echo
    printf '  %-22s %14s %14s %10s\n' "FUNCION (ftrace)" "SIN_MODULO_us" "CON_MODULO_us" "CAMBIO"
    for f in "${FTRACE_FILTER[@]}"; do
        base=$(median_of "$TMP/base.ftrace" "$f")
        shield=$(median_of "$TMP/shield.ftrace" "$f")
        awk -v f="$f" -v a="$base" -v b="$shield" 'BEGIN {
            c = (a + 0 != 0) ? sprintf("%+.1f%%", (b - a) * 100 / a) : "n/a"
            printf "  %-22s %14s %14s %10s\n", f, a, b, c }'
    done
fi
echo
echo "Resultados guardados en $OUT"
