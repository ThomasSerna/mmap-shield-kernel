/*
 * mmap-shield: microbenchmark de mmap, mprotect y fallos de pagina.
 *
 *   bench_mmap [iteraciones] [paginas]
 *
 * Mide en espacio de usuario (clock_gettime) el coste medio de las operaciones
 * que intercepta el modulo y el de los fallos de pagina, que el modulo no
 * intercepta. Imprime una linea "metrica valor" por resultado para que
 * tests/measure_overhead.sh pueda comparar ejecuciones sin y con el modulo.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

/* Default fault-around window (/sys/kernel/debug/fault_around_bytes) */
#define FAULT_AROUND_BYTES (64 * 1024)

static double now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static void *map_or_die(size_t len, int prot, int flags, int fd)
{
    void *p = mmap(NULL, len, prot, flags, fd, 0);

    if (p == MAP_FAILED) {
        fprintf(stderr, "mmap fallo (prot=0x%x flags=0x%x): %s\n", prot, flags, strerror(errno));
        exit(1);
    }
    return p;
}

/*
 * Maps the file read-only at an address aligned to the fault-around window.
 * Each read fault then maps a whole window, so the number of faults per
 * mapping is constant (pages / 16). With the address chosen by ASLR it is 4 or
 * 5 for 64 pages depending on the alignment, and the cost per fault changes
 * with it.
 */
static volatile unsigned char *map_aligned_or_die(size_t len, int fd)
{
    size_t span = len + FAULT_AROUND_BYTES;
    uintptr_t base = (uintptr_t)map_or_die(span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1);
    uintptr_t start = (base + FAULT_AROUND_BYTES - 1) & ~(uintptr_t)(FAULT_AROUND_BYTES - 1);
    void *p = mmap((void *)start, len, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 0);

    if (p == MAP_FAILED) {
        fprintf(stderr, "mmap MAP_FIXED fallo: %s\n", strerror(errno));
        exit(1);
    }
    /* Release the parts of the reservation around the mapping */
    if (start > base)
        munmap((void *)base, start - base);
    munmap((void *)(start + len), base + span - (start + len));
    return p;
}

/* mmap + munmap of the same region, iters times. Returns ns per pair. */
static double bench_map_unmap(long iters, size_t len, int prot, int flags, int fd)
{
    double t0 = now_ns();

    for (long i = 0; i < iters; i++)
        munmap(map_or_die(len, prot, flags, fd), len);
    return (now_ns() - t0) / (double)iters;
}

/* Toggles the protection of a mapping, iters times. Returns ns per mprotect call. */
static double bench_mprotect(long iters, void *p, size_t len, int prot_a, int prot_b)
{
    double t0 = now_ns();

    for (long i = 0; i < iters; i++) {
        if (mprotect(p, len, prot_a) || mprotect(p, len, prot_b)) {
            fprintf(stderr, "mprotect fallo: %s\n", strerror(errno));
            exit(1);
        }
    }
    return (now_ns() - t0) / (double)(2 * iters);
}

int main(int argc, char *argv[])
{
    long iters = argc > 1 ? atol(argv[1]) : 20000;
    long pages = argc > 2 ? atol(argv[2]) : 64;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t len;
    char tmpl[] = "/tmp/mmap-shield-bench-XXXXXX";
    char *data;
    int fd;

    if (iters < 1 || pages < 1 || pages > 65536) {
        fprintf(stderr, "Uso: %s [iteraciones>=1] [paginas 1..65536]\n", argv[0]);
        return 2;
    }
    len = (size_t)pages * page;

    /* Backing file filled with data so that read faults hit the page cache */
    fd = mkstemp(tmpl);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    unlink(tmpl);
    data = malloc(len);
    if (!data) {
        close(fd);
        return 1;
    }
    memset(data, 'B', len);
    if (write(fd, data, len) != (ssize_t)len) {
        perror("write");
        return 1;
    }
    free(data);

    /* Intercepted by security_mmap_file */
    double file_r = bench_map_unmap(iters, len, PROT_READ, MAP_PRIVATE, fd);
    double file_rw = bench_map_unmap(iters, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd);
    double anon = bench_map_unmap(iters, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1);

    /* Intercepted by security_file_mprotect */
    void *a = map_or_die(len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1);
    double mprot_anon = bench_mprotect(iters, a, len, PROT_READ, PROT_READ | PROT_WRITE);
    munmap(a, len);
    void *f = map_or_die(len, PROT_READ, MAP_PRIVATE, fd);
    double mprot_file = bench_mprotect(iters, f, len, PROT_READ | PROT_WRITE, PROT_READ);
    munmap(f, len);

    /* Page faults: not intercepted, measured to show the module does not touch them */
    long fault_rounds = iters / 20 > 0 ? iters / 20 : 1;
    double touch_ns = 0;
    long faults = 0;
    unsigned long checksum = 0;
    for (long r = 0; r < fault_rounds; r++) {
        struct rusage before, after;
        volatile unsigned char *p = map_aligned_or_die(len, fd);

        getrusage(RUSAGE_SELF, &before);
        double t0 = now_ns();
        for (size_t off = 0; off < len; off += page)
            checksum += p[off];
        touch_ns += now_ns() - t0;
        getrusage(RUSAGE_SELF, &after);
        faults += (after.ru_minflt - before.ru_minflt) + (after.ru_majflt - before.ru_majflt);
        munmap((void *)p, len);
    }
    close(fd);

    if (checksum != (unsigned long)fault_rounds * (unsigned long)pages * 'B') {
        fprintf(stderr, "checksum inesperado\n");
        return 1;
    }

    printf("mmap_munmap_file_r_ns %.1f\n", file_r);
    printf("mmap_munmap_file_rw_ns %.1f\n", file_rw);
    printf("mmap_munmap_anon_ns %.1f\n", anon);
    printf("mprotect_anon_ns %.1f\n", mprot_anon);
    printf("mprotect_file_ns %.1f\n", mprot_file);
    printf("page_fault_ns %.1f\n", faults ? touch_ns / (double)faults : 0.0);
    printf("faults_per_mapping %.2f\n", (double)faults / (double)fault_rounds);
    return 0;
}
