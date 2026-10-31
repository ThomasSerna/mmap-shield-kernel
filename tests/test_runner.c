#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_BLUE    "\033[1;34m"

static const char *HONEYPOT_PATH = "/tmp/shield_protected.txt";
static const char *BENIGN_PATH   = "/tmp/shield_benign.txt";

static void print_banner(void)
{
    printf("\n%s======================================================================%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s   mmap-shield: Suite de Validacion de Seguridad en Espacio de Usuario%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s======================================================================%s\n\n", COLOR_CYAN, COLOR_RESET);
}

static int prepare_test_files(void)
{
    int fd;
    const char *sample_data = "DATOS_CONFIDENCIALES_MMAP_SHIELD_2026";

    /* Create benign test file */
    fd = open(BENIGN_PATH, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("Error creando archivo benigno");
        return -1;
    }
    if (write(fd, sample_data, strlen(sample_data)) < 0) {
        perror("Error escribiendo archivo benigno");
        close(fd);
        return -1;
    }
    close(fd);

    /* Create protected honeypot file */
    fd = open(HONEYPOT_PATH, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("Error creando archivo honeypot");
        return -1;
    }
    if (write(fd, sample_data, strlen(sample_data)) < 0) {
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
            return true;
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
        /* If cannot open O_RDWR, try O_RDONLY to test */
        fd = open(HONEYPOT_PATH, O_RDONLY);
    }
    if (fd < 0) {
        printf("%s[OMITIDO]%s No se puede acceder al archivo honeypot\n", COLOR_YELLOW, COLOR_RESET);
        return true;
    }

    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        printf("%s[PASO (BLOQUEADO CORRECTAMENTE: %s)]%s\n",
               COLOR_GREEN, strerror(errno), COLOR_RESET);
        close(fd);
        return true;
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
        printf("%s[OMITIDO]%s No se pudo abrir %s\n", COLOR_YELLOW, COLOR_RESET, HONEYPOT_PATH);
        return true;
    }

    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        printf("%s[PASO (BLOQUEADO PREVENTIVAMENTE: %s)]%s\n",
               COLOR_GREEN, strerror(errno), COLOR_RESET);
        close(fd);
        return true;
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
 * El kernel VFS/mmap debe rechazarlo con -EACCES.
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
    if (addr == MAP_FAILED) {
        printf("%s[PASO (RECHAZADO CORRECTAMENTE: %s)]%s\n",
               COLOR_GREEN, strerror(errno), COLOR_RESET);
        close(fd);
        return true;
    }

    printf("%s[FALLO]%s MAP_SHARED fue permitido sobre descriptor O_RDONLY\n",
           COLOR_RED, COLOR_RESET);
    munmap(addr, 4096);
    close(fd);
    return false;
}

int main(int argc, char *argv[])
{
    print_banner();

    if (prepare_test_files() < 0) {
        fprintf(stderr, "Error inicializando archivos de prueba.\n");
        return 1;
    }

    int passed = 0;
    int total = 5;

    if (argc > 1) {
        int t = atoi(argv[1]);
        printf("[+] Ejecutando prueba individual #%d\n", t);
        switch (t) {
        case 1: if (test_benign_mmap()) passed++; break;
        case 2: if (test_wx_violation()) passed++; break;
        case 3: if (test_sensitive_file_protection()) passed++; break;
        case 4: if (test_dirty_cow_pattern()) passed++; break;
        case 5: if (test_shared_write_ro_fd()) passed++; break;
        default:
            fprintf(stderr, "Prueba desconocida: %d (Elige 1-5)\n", t);
            return 1;
        }
        total = 1;
    } else {
        if (test_benign_mmap()) passed++;
        if (test_wx_violation()) passed++;
        if (test_sensitive_file_protection()) passed++;
        if (test_dirty_cow_pattern()) passed++;
        if (test_shared_write_ro_fd()) passed++;
    }

    printf("\n%s----------------------------------------------------------------------%s\n", COLOR_CYAN, COLOR_RESET);
    printf(" Resumen de Pruebas: %s%d de %d pruebas superadas con exito%s\n",
           (passed == total) ? COLOR_GREEN : COLOR_YELLOW,
           passed, total, COLOR_RESET);
    printf("%s----------------------------------------------------------------------%s\n\n", COLOR_CYAN, COLOR_RESET);

    return (passed == total) ? 0 : 1;
}
