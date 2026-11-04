#!/usr/bin/env python3
"""Compare mmap and page-fault measurements before and after loading the module."""

import argparse
import json
import mmap
import os
import platform
import sys
import tempfile
import time
from pathlib import Path


def measure(iterations, pages):
    import resource

    size = pages * mmap.PAGESIZE
    mmap_ns = touch_ns = minor_faults = major_faults = 0
    checksum = 0
    with tempfile.TemporaryFile() as file:
        file.write(b"\0" * size)
        file.flush()
        for _ in range(iterations):
            start = time.perf_counter_ns()
            region = mmap.mmap(file.fileno(), size, access=mmap.ACCESS_READ)
            mmap_ns += time.perf_counter_ns() - start
            before = resource.getrusage(resource.RUSAGE_SELF)
            start = time.perf_counter_ns()
            for offset in range(0, size, mmap.PAGESIZE):
                checksum += region[offset]
            touch_ns += time.perf_counter_ns() - start
            after = resource.getrusage(resource.RUSAGE_SELF)
            minor_faults += after.ru_minflt - before.ru_minflt
            major_faults += after.ru_majflt - before.ru_majflt
            region.close()
    assert checksum == 0
    return {"mmap_ns_per_call": mmap_ns / iterations,
            "touch_ns": touch_ns, "minor_faults": minor_faults,
            "major_faults": major_faults,
            "faults_per_second": (minor_faults + major_faults) * 1e9 / touch_ns}


def main():
    parser = argparse.ArgumentParser(
        description="Compara mmap y fallos de página sobre el mismo trabajo con y sin mmap_shield.",
        epilog="Ejecute primero 'baseline archivo.json' sin módulo y luego 'compare archivo.json' "
               "con el módulo cargado. El programa no carga ni descarga módulos; "
               "use las mismas opciones y condiciones en ambas ejecuciones. "
               "Usa un archivo temporal propio y no sobrescribe resultados existentes.")
    parser.add_argument("phase", choices=("baseline", "compare"))
    parser.add_argument("file", type=Path, help="archivo JSON de referencia")
    parser.add_argument("--iterations", type=int, default=1000, help="mapeos (por defecto: 1000)")
    parser.add_argument("--pages", type=int, default=64, help="páginas por mapeo (por defecto: 64)")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("se requiere Linux")
    if args.iterations < 1 or not 1 <= args.pages <= 4096:
        parser.error("iterations debe ser positivo y pages debe estar entre 1 y 4096")

    loaded = Path("/sys/module/mmap_shield").is_dir()
    if loaded != (args.phase == "compare"):
        parser.error("baseline requiere el módulo descargado; compare requiere el módulo cargado")
    config = {"kernel": platform.release(), "iterations": args.iterations,
              "pages": args.pages, "page_size": mmap.PAGESIZE, "uid": os.getuid()}
    if args.phase == "compare":
        with args.file.open(encoding="utf-8") as file:
            baseline = json.load(file)
        if baseline["config"] != config:
            parser.error("el kernel, usuario o parámetros difieren de la referencia")

    result = {"config": config, "metrics": measure(args.iterations, args.pages)}
    if Path("/sys/module/mmap_shield").is_dir() != loaded:
        parser.error("el estado del módulo cambió durante la medición")
    if args.phase == "baseline":
        with args.file.open("x", encoding="utf-8") as file:
            json.dump(result, file, indent=2)
            file.write("\n")
        print(f"Referencia guardada en {args.file}")
    else:
        old, new = baseline["metrics"], result["metrics"]
        for key, label in (("mmap_ns_per_call", "mmap (ns/llamada)"),
                           ("faults_per_second", "fallos de página/s")):
            change = f"{(new[key] / old[key] - 1) * 100:+.2f}%" if old[key] else "no calculable"
            print(f"{label}: sin módulo {old[key]:.2f}; con módulo {new[key]:.2f}; cambio {change}")
        for label, metrics in (("sin módulo", old), ("con módulo", new)):
            print(f"{label}: {metrics['minor_faults']} fallos menores, "
                  f"{metrics['major_faults']} mayores, {metrics['touch_ns'] / 1e9:.3f} s tocando páginas")
        print("Incluye coste de Python y ruido del sistema; no mide latencia pura del kernel.")


if __name__ == "__main__":
    main()
