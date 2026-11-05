#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <limits.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_BLUE    "\033[1;34m"

#define SAMPLE_DATA "DATOS_CONFIDENCIALES_MMAP_SHIELD_2026"

static char HONEYPOT_PATH[PATH_MAX];
static char BENIGN_PATH[PATH_MAX];
static char ALIAS_PATH[PATH_MAX];

static void print_banner(void)
{
    printf("\n%s======================================================================%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s   mmap-shield: Suite de Validacion de Seguridad en Espacio de Usuario%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s======================================================================%s\n\n", COLOR_CYAN, COLOR_RESET);
}

/*
 * Creates the test files. When the directory is provided by run_tests.sh the
 * files already exist (they are registered in the module before the tests so
 * their inode is recorded): they are rewritten in place, keeping the inode.
 */
static int prepare_test_files(bool external_dir)
{
    int fd;
    const char *sample_data = SAMPLE_DATA;
    int oflags = O_RDWR | O_CREAT | O_NOFOLLOW | (external_dir ? O_TRUNC : O_EXCL);

    /* Create benign test file */
    fd = open(BENIGN_PATH, oflags, 0600);
    if (fd < 0) {
        perror("Error creando archivo benigno");
        return -1;
    }
    if (write(fd, sample_data, strlen(sample_data)) != (ssize_t)strlen(sample_data)) {
        perror("Error escribiendo archivo benigno");
        close(fd);
        return -1;
    }
    close(fd);

    /* Create protected honeypot file */
    fd = open(HONEYPOT_PATH, oflags, 0600);
    if (fd < 0) {
        perror("Error creando archivo honeypot");
        return -1;
    }
    if (write(fd, sample_data, strlen(sample_data)) != (ssize_t)strlen(sample_data)) {
        perror("Error escribiendo archivo honeypot");
        close(fd);
        return -1;
    }
    close(fd);

    return 0;
}

/*
 * TEST 1: Mapeo benigno legitimo (O_RDONLY con PROT_READ y MAP_PRIVATE)
 * Debe permitirse sin ninguna restriccion.
 */
static bool test_benign_mmap(void)
{
    printf("[*] TEST 1: Mapeo de memoria legitimo (Lectura regular)... ");
    int fd = open(BENIGN_PATH, O_RDONLY);
    if (fd < 0) {
        printf("%s[FALLO]%s No se pudo abrir %s\n", COLOR_RED, COLOR_RESET, BENIGN_PATH);
        return false;
    }

    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        printf("%s[FALLO]%s mmap legitimo fue bloqueado inesperadamente (errno=%d: %s)\n",
               COLOR_RED, COLOR_RESET, errno, strerror(errno));
        close(fd);
        return false;
    }

    /* Verify content read */
    if (strncmp((char *)addr, "DATOS_CONFIDENCIALES", 20) != 0) {
        printf("%s[FALLO]%s Los datos leidos no coinciden\n", COLOR_RED, COLOR_RESET);
        munmap(addr, 4096);
        close(fd);
        return false;
    }

    munmap(addr, 4096);
    close(fd);
    printf("%s[PASO (PERMITIDO)]%s\n", COLOR_GREEN, COLOR_RESET);
    return true;
}

/*
 * TEST 2: Intento de violacion de politica W^X (PROT_WRITE | PROT_EXEC)
 * Debe ser bloqueado por mmap-shield con -EPERM o -EACCES.
 */
static bool test_wx_violation(void)
{
    printf("[*] TEST 2: Violacion de politica W^X (PROT_WRITE | PROT_EXEC)... ");
    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (addr == MAP_FAILED) {
        if (errno == EPERM || errno == EACCES) {
            printf("%s[PASO (BLOQUEADO CORRECTAMENTE: %s)]%s\n",
                   COLOR_GREEN, strerror(errno), COLOR_RESET);
            return true;
        } else {
            printf("%s[ADVERTENCIA]%s Bloqueado con codigo inusual: errno=%d (%s)\n",
                   COLOR_YELLOW, COLOR_RESET, errno, strerror(errno));
            return false;
        }
    }

    printf("%s[FALLO DE SEGURIDAD]%s Mapeo W^X fue permitido indebidamente en %p\n",
           COLOR_RED, COLOR_RESET, addr);
    munmap(addr, 4096);
    return false;
}

/*
 * TEST 3: Intento de mapeo de escritura no autorizado sobre archivo sensible
 * Debe ser bloqueado para usuarios no privilegiados.
 */
static bool test_sensitive_file_protection(void)
{
    printf("[*] TEST 3: Acceso no autorizado a archivo sensible (%s)... ", HONEYPOT_PATH);
    int fd = open(HONEYPOT_PATH, O_RDWR);
    if (fd < 0) {
        printf("%s[FALLO]%s No se puede abrir el archivo honeypot para escritura\n", COLOR_RED, COLOR_RESET);
        return false;
    }

    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED && (errno == EACCES || errno == EPERM)) {
        printf("%s[PASO (BLOQUEADO CORRECTAMENTE: %s)]%s\n",
               COLOR_GREEN, strerror(errno), COLOR_RESET);
        close(fd);
        return true;
    }
    if (addr == MAP_FAILED) {
        perror("mmap archivo sensible");
        close(fd);
        return false;
    }

    printf("%s[FALLO DE SEGURIDAD]%s Escritura compartida en archivo protegido fue permitida en %p\n",
           COLOR_RED, COLOR_RESET, addr);
    munmap(addr, 4096);
    close(fd);
    return false;
}

/*
 * TEST 4: Patron Dirty COW (CVE-2016-5195)
 * Archivo abierto en solo lectura (O_RDONLY) mapeado con MAP_PRIVATE | PROT_WRITE.
 * Debe ser detectado y bloqueado antes de que ocurra la condicion de carrera.
 */
static bool test_dirty_cow_pattern(void)
{
    printf("[*] TEST 4: Simulacion de vector precursor Dirty COW (RO + MAP_PRIVATE|PROT_WRITE)... ");
    int fd = open(HONEYPOT_PATH, O_RDONLY);
    if (fd < 0) {
        printf("%s[FALLO]%s No se pudo abrir %s\n", COLOR_RED, COLOR_RESET, HONEYPOT_PATH);
        return false;
    }

    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED && (errno == EACCES || errno == EPERM)) {
        printf("%s[PASO (BLOQUEADO PREVENTIVAMENTE: %s)]%s\n",
               COLOR_GREEN, strerror(errno), COLOR_RESET);
        close(fd);
        return true;
    }
    if (addr == MAP_FAILED) {
        perror("mmap Dirty COW");
        close(fd);
        return false;
    }

    /* In standard unprotected Linux, POSIX allows this mapping for COW */
    printf("%s[ALERTA]%s Mapeo COW permitido en %p (Verificar si el modulo esta en modo ENFORCING)\n",
           COLOR_YELLOW, COLOR_RESET, addr);
    munmap(addr, 4096);
    close(fd);
    return false;
}

/*
 * TEST 5: Intento de MAP_SHARED con PROT_WRITE sobre descriptor O_RDONLY
 * Debe rechazarse con -EACCES. Con el modulo cargado lo rechaza primero el
 * gancho de security_mmap_file (evento BLOQUEO_SHARED en la auditoria); sin
 * el modulo, do_mmap() tambien lo rechaza, por lo que esta prueba por si sola
 * no distingue ambos casos.
 */
static bool test_shared_write_ro_fd(void)
{
    printf("[*] TEST 5: MAP_SHARED | PROT_WRITE con descriptor O_RDONLY... ");
    int fd = open(BENIGN_PATH, O_RDONLY);
    if (fd < 0) {
        printf("%s[FALLO]%s No se pudo abrir %s\n", COLOR_RED, COLOR_RESET, BENIGN_PATH);
        return false;
    }

    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED && errno == EACCES) {
        printf("%s[PASO (RECHAZADO CORRECTAMENTE: %s)]%s\n",
               COLOR_GREEN, strerror(errno), COLOR_RESET);
        close(fd);
        return true;
    }
    if (addr == MAP_FAILED) {
        perror("mmap MAP_SHARED");
        close(fd);
        return false;
    }

    printf("%s[FALLO]%s MAP_SHARED fue permitido sobre descriptor O_RDONLY\n",
           COLOR_RED, COLOR_RESET);
    munmap(addr, 4096);
    close(fd);
    return false;
}

static bool is_denied(int err)
{
    return err == EACCES || err == EPERM;
}

/* Returns true when the VMA containing addr is readable, writable and executable. */
static bool vma_is_rwx(const void *addr)
{
    char line[512], perms[8];
    unsigned long lo, hi, a = (unsigned long)addr;
    bool rwx = false;
    FILE *maps = fopen("/proc/self/maps", "r");

    if (!maps)
        return false;
    while (fgets(line, sizeof(line), maps)) {
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) == 3 && a >= lo && a < hi) {
            rwx = perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x';
            break;
        }
    }
    fclose(maps);
    return rwx;
}

/*
 * TEST 6: Evasion de W^X en dos pasos: mapeo anonimo RW y luego mprotect a RWX.
 * El gancho de security_file_mprotect debe rechazar el cambio de permisos.
 */
static bool test_mprotect_wx(void)
{
    printf("[*] TEST 6: Evasion W^X con mprotect (RW -> RWX)... ");
    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        printf("%s[FALLO]%s El mapeo RW inicial fue bloqueado (errno=%d: %s)\n",
               COLOR_RED, COLOR_RESET, errno, strerror(errno));
        return false;
    }

    if (mprotect(addr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        printf("%s[FALLO DE SEGURIDAD]%s mprotect a RWX fue permitido en %p\n",
               COLOR_RED, COLOR_RESET, addr);
        munmap(addr, 4096);
        return false;
    }
    int err = errno;
    munmap(addr, 4096);
    if (is_denied(err)) {
        printf("%s[PASO (BLOQUEADO CORRECTAMENTE: %s)]%s\n", COLOR_GREEN, strerror(err), COLOR_RESET);
        return true;
    }
    printf("%s[ADVERTENCIA]%s Rechazado con codigo inusual: errno=%d (%s)\n",
           COLOR_YELLOW, COLOR_RESET, err, strerror(err));
    return false;
}

/*
 * TEST 7: Personalidad READ_IMPLIES_EXEC. El kernel agrega PROT_EXEC a un
 * mmap(PROT_READ | PROT_WRITE), que termina siendo RWX sin pedirlo. El modulo
 * debe evaluar la proteccion efectiva y no solo la solicitada.
 */
static bool test_read_implies_exec(void)
{
    printf("[*] TEST 7: Evasion W^X con personalidad READ_IMPLIES_EXEC... ");
    int old = personality(0xffffffff);
    if (old == -1 || personality((unsigned long)old | READ_IMPLIES_EXEC) == -1) {
        printf("%s[FALLO]%s No se pudo cambiar la personalidad (errno=%d: %s)\n",
               COLOR_RED, COLOR_RESET, errno, strerror(errno));
        return false;
    }
    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int err = errno;
    personality((unsigned long)old);

    if (addr == MAP_FAILED && is_denied(err)) {
        printf("%s[PASO (BLOQUEADO CORRECTAMENTE: %s)]%s\n", COLOR_GREEN, strerror(err), COLOR_RESET);
        return true;
    }
    if (addr == MAP_FAILED) {
        printf("%s[ADVERTENCIA]%s Rechazado con codigo inusual: errno=%d (%s)\n",
               COLOR_YELLOW, COLOR_RESET, err, strerror(err));
        return false;
    }
    printf("%s[FALLO DE SEGURIDAD]%s Mapeo permitido en %p (VMA %s)\n", COLOR_RED, COLOR_RESET,
           addr, vma_is_rwx(addr) ? "RWX" : "sin RWX");
    munmap(addr, 4096);
    return false;
}

/*
 * TEST 8: Doble mapeo de un memfd: una vista para escribir y otra para
 * ejecutar. Ninguna llamada pide W y X a la vez, pero el codigo escrito por
 * una vista se ejecuta por la otra. La vista ejecutable debe rechazarse tanto
 * despues como antes de crear la vista escribible.
 */
static bool test_memfd_alias(void)
{
    printf("[*] TEST 8: Alias W^X con doble mapeo de memfd (RW + RX)... ");
    int fd = memfd_create("mmap-shield-alias", 0);
    if (fd < 0 || ftruncate(fd, 4096) != 0) {
        printf("%s[FALLO]%s No se pudo preparar el memfd (errno=%d: %s)\n",
               COLOR_RED, COLOR_RESET, errno, strerror(errno));
        if (fd >= 0)
            close(fd);
        return false;
    }

    /* Executable view first: descriptor is writable, so it must be denied already */
    void *x_first = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    int err_first = errno;

    void *w = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (w == MAP_FAILED) {
        printf("%s[FALLO]%s La vista de escritura fue bloqueada inesperadamente (errno=%d: %s)\n",
               COLOR_RED, COLOR_RESET, errno, strerror(errno));
        if (x_first != MAP_FAILED)
            munmap(x_first, 4096);
        close(fd);
        return false;
    }
    void *x_after = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    int err_after = errno;

    bool ok = x_first == MAP_FAILED && is_denied(err_first) &&
              x_after == MAP_FAILED && is_denied(err_after);
    if (ok) {
        printf("%s[PASO (BLOQUEADO CORRECTAMENTE: %s)]%s\n", COLOR_GREEN, strerror(err_after), COLOR_RESET);
    } else {
        printf("%s[FALLO DE SEGURIDAD]%s Vista ejecutable %s antes y %s despues de la escribible\n",
               COLOR_RED, COLOR_RESET,
               x_first == MAP_FAILED ? "rechazada" : "permitida",
               x_after == MAP_FAILED ? "rechazada" : "permitida");
    }
    if (x_first != MAP_FAILED)
        munmap(x_first, 4096);
    if (x_after != MAP_FAILED)
        munmap(x_after, 4096);
    munmap(w, 4096);
    close(fd);
    return ok;
}

/*
 * TEST 9: Precursor Dirty COW en dos pasos: el archivo protegido se abre en
 * solo lectura, se mapea MAP_PRIVATE | PROT_READ (permitido) y luego se pide
 * PROT_WRITE con mprotect. Es el mismo VMA que el TEST 4 y debe rechazarse.
 */
static bool test_dirty_cow_mprotect(void)
{
    printf("[*] TEST 9: Precursor Dirty COW via mprotect (RO + MAP_PRIVATE, luego PROT_WRITE)... ");
    int fd = open(HONEYPOT_PATH, O_RDONLY);
    if (fd < 0) {
        printf("%s[FALLO]%s No se pudo abrir %s\n", COLOR_RED, COLOR_RESET, HONEYPOT_PATH);
        return false;
    }
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        printf("%s[FALLO]%s El mapeo de solo lectura fue bloqueado (errno=%d: %s)\n",
               COLOR_RED, COLOR_RESET, errno, strerror(errno));
        close(fd);
        return false;
    }

    int r = mprotect(addr, 4096, PROT_READ | PROT_WRITE);
    int err = errno;
    munmap(addr, 4096);
    close(fd);
    if (r != 0 && is_denied(err)) {
        printf("%s[PASO (BLOQUEADO CORRECTAMENTE: %s)]%s\n", COLOR_GREEN, strerror(err), COLOR_RESET);
        return true;
    }
    if (r != 0) {
        printf("%s[ADVERTENCIA]%s Rechazado con codigo inusual: errno=%d (%s)\n",
               COLOR_YELLOW, COLOR_RESET, err, strerror(err));
        return false;
    }
    printf("%s[FALLO DE SEGURIDAD]%s mprotect concedio PROT_WRITE sobre la copia COW del archivo protegido\n",
           COLOR_RED, COLOR_RESET);
    return false;
}

/*
 * TEST 10: Enlace duro al archivo protegido. La ruta es otra, pero el inodo es
 * el mismo: el mapeo escribible compartido debe rechazarse y el contenido del
 * archivo protegido no debe cambiar.
 */
static bool test_hardlink_alias(void)
{
    printf("[*] TEST 10: Enlace duro al archivo protegido (otra ruta, mismo inodo)... ");
    unlink(ALIAS_PATH);
    if (link(HONEYPOT_PATH, ALIAS_PATH) != 0) {
        printf("%s[ADVERTENCIA]%s No se pudo crear el enlace duro (errno=%d: %s)\n",
               COLOR_YELLOW, COLOR_RESET, errno, strerror(errno));
        return false;
    }

    bool ok = false;
    int fd = open(ALIAS_PATH, O_RDWR);
    void *addr = fd >= 0 ? mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) : MAP_FAILED;
    int err = errno;
    if (addr != MAP_FAILED) {
        memcpy(addr, "PWNED", 5);
        msync(addr, 4096, MS_SYNC);
        munmap(addr, 4096);
    }
    if (fd >= 0)
        close(fd);
    unlink(ALIAS_PATH);

    char content[sizeof(SAMPLE_DATA)] = {0};
    fd = open(HONEYPOT_PATH, O_RDONLY);
    bool intact = fd >= 0 && read(fd, content, sizeof(content) - 1) > 0 &&
                  strcmp(content, SAMPLE_DATA) == 0;
    if (fd >= 0)
        close(fd);

    if (addr == MAP_FAILED && is_denied(err) && intact) {
        printf("%s[PASO (BLOQUEADO CORRECTAMENTE: %s)]%s\n", COLOR_GREEN, strerror(err), COLOR_RESET);
        ok = true;
    } else if (addr == MAP_FAILED && intact) {
        printf("%s[ADVERTENCIA]%s Rechazado con codigo inusual: errno=%d (%s)\n",
               COLOR_YELLOW, COLOR_RESET, err, strerror(err));
    } else {
        printf("%s[FALLO DE SEGURIDAD]%s El archivo protegido %s a traves del enlace duro\n",
               COLOR_RED, COLOR_RESET, intact ? "pudo mapearse con escritura" : "fue modificado");
    }
    return ok;
}

/*
 * TEST 11: Escritura compartida en dos pasos: el archivo protegido se mapea
 * MAP_SHARED | PROT_READ (permitido) con un descriptor de lectura/escritura y
 * luego se pide PROT_WRITE con mprotect. Debe rechazarse como el TEST 3.
 */
static bool test_sensitive_mprotect(void)
{
    printf("[*] TEST 11: Escritura compartida en archivo protegido via mprotect... ");
    int fd = open(HONEYPOT_PATH, O_RDWR);
    if (fd < 0) {
        printf("%s[FALLO]%s No se pudo abrir %s\n", COLOR_RED, COLOR_RESET, HONEYPOT_PATH);
        return false;
    }
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        printf("%s[FALLO]%s El mapeo de solo lectura fue bloqueado (errno=%d: %s)\n",
               COLOR_RED, COLOR_RESET, errno, strerror(errno));
        close(fd);
        return false;
    }

    int r = mprotect(addr, 4096, PROT_READ | PROT_WRITE);
    int err = errno;
    munmap(addr, 4096);
    close(fd);
    if (r != 0 && is_denied(err)) {
        printf("%s[PASO (BLOQUEADO CORRECTAMENTE: %s)]%s\n", COLOR_GREEN, strerror(err), COLOR_RESET);
        return true;
    }
    if (r != 0) {
        printf("%s[ADVERTENCIA]%s Rechazado con codigo inusual: errno=%d (%s)\n",
               COLOR_YELLOW, COLOR_RESET, err, strerror(err));
        return false;
    }
    printf("%s[FALLO DE SEGURIDAD]%s mprotect concedio escritura compartida sobre el archivo protegido\n",
           COLOR_RED, COLOR_RESET);
    return false;
}

#define NUM_TESTS 11

static bool run_test(int t)
{
    switch (t) {
    case 1:  return test_benign_mmap();
    case 2:  return test_wx_violation();
    case 3:  return test_sensitive_file_protection();
    case 4:  return test_dirty_cow_pattern();
    case 5:  return test_shared_write_ro_fd();
    case 6:  return test_mprotect_wx();
    case 7:  return test_read_implies_exec();
    case 8:  return test_memfd_alias();
    case 9:  return test_dirty_cow_mprotect();
    case 10: return test_hardlink_alias();
    case 11: return test_sensitive_mprotect();
    default:
        fprintf(stderr, "Prueba desconocida: %d (Elige 1-%d)\n", t, NUM_TESTS);
        return false;
    }
}

int main(int argc, char *argv[])
{
    char temp_dir[] = "/tmp/mmap-shield-test-XXXXXX";
    const char *dir = getenv("SHIELD_TEST_DIR");
    bool own_dir = false;

    print_banner();

    if (!dir) {
        dir = mkdtemp(temp_dir);
        own_dir = true;
    }
    if (!dir || snprintf(BENIGN_PATH, sizeof(BENIGN_PATH), "%s/benign", dir) >= (int)sizeof(BENIGN_PATH) ||
        snprintf(HONEYPOT_PATH, sizeof(HONEYPOT_PATH), "%s/protected", dir) >= (int)sizeof(HONEYPOT_PATH) ||
        snprintf(ALIAS_PATH, sizeof(ALIAS_PATH), "%s/alias", dir) >= (int)sizeof(ALIAS_PATH)) {
        fprintf(stderr, "Directorio de prueba invalido o demasiado largo.\n");
        return 1;
    }

    if (prepare_test_files(!own_dir) < 0) {
        fprintf(stderr, "Error inicializando archivos de prueba.\n");
        if (own_dir) {
            unlink(BENIGN_PATH);
            unlink(HONEYPOT_PATH);
            rmdir(dir);
        }
        return 1;
    }

    int passed = 0;
    int total = NUM_TESTS;

    if (argc > 1) {
        int t = atoi(argv[1]);
        printf("[+] Ejecutando prueba individual #%d\n", t);
        if (run_test(t))
            passed++;
        total = 1;
    } else {
        for (int t = 1; t <= NUM_TESTS; t++) {
            if (run_test(t))
                passed++;
        }
    }

    printf("\n%s----------------------------------------------------------------------%s\n", COLOR_CYAN, COLOR_RESET);
    printf(" Resumen de Pruebas: %s%d de %d pruebas superadas con exito%s\n",
           (passed == total) ? COLOR_GREEN : COLOR_YELLOW,
           passed, total, COLOR_RESET);
    printf("%s----------------------------------------------------------------------%s\n\n", COLOR_CYAN, COLOR_RESET);

    /* Files in a directory provided by run_tests.sh are removed by the script */
    if (own_dir) {
        unlink(BENIGN_PATH);
        unlink(HONEYPOT_PATH);
        rmdir(dir);
    }
    return (passed == total) ? 0 : 1;
}
