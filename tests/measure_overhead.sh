#!/usr/bin/env bash
# Mide el sobrecosto de mmap-shield comparando el mismo trabajo sin y con el
# modulo cargado:
#   - tests/bench_mmap: coste por llamada medido en espacio de usuario
#   - perf stat:        fallos de pagina y cambios de contexto (si perf esta disponible)
#   - strace -c:        tiempo por llamada al sistema (si strace esta disponible)
#   - ftrace:           latencia en kernel de mmap, mprotect y handle_mm_fault (function_graph)
# El resultado se guarda en results/overhead-<kernel>.txt.
# Variables opcionales: ITERATIONS (20000), PAGES (64), REPS (5).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ITERATIONS=${ITERATIONS:-20000}
PAGES=${PAGES:-64}
REPS=${REPS:-5}
FTRACE_ITERATIONS=$((ITERATIONS / 20))
BENCH="$SCRIPT_DIR/bench_mmap"
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
if [[ ! -f "$ROOT_DIR/mmap_shield.ko" ]]; then
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
TRACEFS=/sys/kernel/tracing
[[ -e "$TRACEFS/current_tracer" ]] || TRACEFS=/sys/kernel/debug/tracing

mkdir -p "$ROOT_DIR/results"
OUT="$ROOT_DIR/results/overhead-$(uname -r).txt"
TMP=$(mktemp -d)
loaded=0

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
    if [[ $loaded -eq 1 ]]; then
        rmmod mmap_shield || status=1
    fi
    rm -rf -- "$TMP"
    exit "$status"
}
trap cleanup EXIT

exec > >(tee "$OUT") 2>&1

median_of() {  # $1 = archivo de bench, $2 = metrica
    awk -v m="$2" '$1 == m { print $2 }' "$1" | sort -n |
        awk '{ v[NR] = $1 } END { if (NR == 0) print "n/a"; else if (NR % 2) print v[(NR + 1) / 2];
                                  else printf "%.1f\n", (v[NR / 2] + v[NR / 2 + 1]) / 2 }'
}

# function_graph with the filter limited to a few functions prints each call as
# a leaf with its total duration (including everything it calls). Every task is
# traced and the lines of the benchmark are selected by process name
# (funcgraph-proc), with a ring buffer large enough to keep all the events.
ftrace_measure() {  # $1 = prefijo de salida
    local funcs=() f old_kb lost
    if [[ ! -e "$TRACEFS/current_tracer" ]] || ! grep -qw function_graph "$TRACEFS/available_tracers"; then
        echo "  (ftrace function_graph no disponible)"
        return
    fi
    ftrace_reset
    for f in "${FTRACE_FUNCS[@]}"; do
        if awk -v f="$f" '$1 == f { found = 1; exit } END { exit !found }' "$TRACEFS/available_filter_functions"; then
            funcs+=("$f")
        fi
    done
    old_kb=$(awk '{ print $1; exit }' "$TRACEFS/buffer_size_kb")
    echo 8192 > "$TRACEFS/buffer_size_kb"
    printf '%s\n' "${funcs[@]}" > "$TRACEFS/set_ftrace_filter"
    echo function_graph > "$TRACEFS/current_tracer"
    echo 1 > "$TRACEFS/options/funcgraph-proc"
    echo > "$TRACEFS/trace"
    echo 1 > "$TRACEFS/tracing_on"
    "$BENCH" "$FTRACE_ITERATIONS" "$PAGES" > /dev/null
    echo 0 > "$TRACEFS/tracing_on"
    lost=$(cat "$TRACEFS"/per_cpu/cpu*/stats | awk '/^(overrun|dropped events):/ { s += $NF } END { print s + 0 }')
    cp "$TRACEFS/trace" "$TMP/$1.trace"
    echo 0 > "$TRACEFS/options/funcgraph-proc"
    ftrace_reset
    echo "$old_kb" > "$TRACEFS/buffer_size_kb"
    echo "  (eventos perdidos por desbordamiento del buffer: $lost)"
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
               END { for (f in n) printf "  %-22s llamadas=%-8d media_us=%.3f\n", f, n[f], sum[f] / n[f] }' \
        "$TMP/$1.trace" | sort | tee "$TMP/$1.ftrace"
}

phase() {  # $1 = etiqueta, $2 = prefijo
    local m r
    echo
    echo "################ $1 ################"
    for r in $(seq 1 "$REPS"); do
        "$BENCH" "$ITERATIONS" "$PAGES"
    done > "$TMP/$2.bench"
    echo "--- bench_mmap: mediana de $REPS ejecuciones ($ITERATIONS iteraciones, $PAGES paginas) ---"
    for m in "${METRICS[@]}"; do
        printf '  %-26s %s\n' "$m" "$(median_of "$TMP/$2.bench" "$m")"
    done

    echo "--- perf stat ---"
    if [[ -n "$PERF" ]]; then
        "$PERF" stat -e page-faults,minor-faults,major-faults,context-switches,task-clock -r "$REPS" \
            -- "$BENCH" "$ITERATIONS" "$PAGES" 2>&1 >/dev/null | sed -n '/Performance counter/,$p' ||
            echo "  (perf stat fallo)"
    else
        echo "  (perf no disponible)"
    fi

    echo "--- strace -c (mmap, mprotect, munmap; $FTRACE_ITERATIONS iteraciones) ---"
    if [[ -n "$STRACE" ]]; then
        if "$STRACE" -c -e trace=mmap,mprotect,munmap -o "$TMP/$2.strace" \
            "$BENCH" "$FTRACE_ITERATIONS" "$PAGES" > /dev/null; then
            cat "$TMP/$2.strace"
        else
            echo "  (strace fallo)"
        fi
    else
        echo "  (strace no disponible)"
    fi

    echo "--- ftrace function_graph: latencia en kernel ($FTRACE_ITERATIONS iteraciones) ---"
    ftrace_measure "$2"
}

echo "mmap-shield: medicion de sobrecosto"
echo "Fecha:       $(date -Iseconds)"
echo "Kernel:      $(uname -r)"
echo "CPU:         $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
echo "Parametros:  ITERATIONS=$ITERATIONS PAGES=$PAGES REPS=$REPS"
echo "Herramientas: perf=${PERF:-no} strace=${STRACE:-no} ftrace=$TRACEFS"

phase "SIN MODULO" base

$INSMOD "$ROOT_DIR/mmap_shield.ko"
loaded=1
phase "CON MODULO (enforcing, todas las politicas)" shield
echo "--- Telemetria del modulo durante la medicion ---"
grep -E "interceptadas|mprotect:|permitidos|bloqueados" /proc/mmap_shield
rmmod mmap_shield
loaded=0

echo
echo "################ RESUMEN (medianas) ################"
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
    join <(awk '{ split($3, v, "="); print $1, v[2] }' "$TMP/base.ftrace" | sort) \
         <(awk '{ split($3, v, "="); print $1, v[2] }' "$TMP/shield.ftrace" | sort) |
        awk '{ c = ($2 + 0 != 0) ? sprintf("%+.1f%%", ($3 - $2) * 100 / $2) : "n/a"
               printf "  %-22s %14s %14s %10s\n", $1, $2, $3, c }'
fi
echo
echo "Resultados guardados en $OUT"
