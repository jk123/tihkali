/* tihkali Linux-ABI depth probe: exercises the full deferred syscall set
 * through musl wrappers. Exit code = number of failed checks (0 = pass). */
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int fails;

#define OK(cond, name)                                                     \
    do {                                                                   \
        if (!(cond)) {                                                     \
            static const char f[] = "FAIL: " name "\n";                    \
            write(1, f, sizeof(f) - 1);                                   \
            fails++;                                                       \
        }                                                                  \
    } while (0)

static volatile int got;

static void handler(int s) {
    got = s;
}

int main(void) {
    /* --- files: openat / write / lseek / read / close / fstat --- */
    int fd = open("/probe", O_RDWR | O_CREAT | O_TRUNC, 0644);
    OK(fd >= 0, "open O_CREAT");
    write(fd, "abcdef", 6);
    OK(lseek(fd, 2, SEEK_SET) == 2, "lseek SET");
    char b[4];
    int n = read(fd, b, 3);
    OK(n == 3 && b[0] == 'c' && b[2] == 'e', "lseek+read");
    struct stat st;
    OK(fstat(fd, &st) == 0, "fstat call");
    OK(st.st_size == 6 && S_ISREG(st.st_mode), "fstat fields");
    OK(lseek(fd, 0, SEEK_END) == 6, "lseek END");
    close(fd);
    fd = open("/probe", O_RDONLY);
    OK(fd >= 0, "reopen");
    close(fd);

    /* --- uname --- */
    struct utsname u;
    OK(uname(&u) == 0, "uname call");
    OK(strcmp(u.sysname, "Linux") == 0, "uname sysname");
    OK(strcmp(u.machine, "aarch64") == 0, "uname machine");

    /* --- brk (+ demand-faulted page) ---
     * musl's sbrk in this toolchain only services delta==0 (grow returns
     * -ENOMEM without a syscall), so drive brk(214) directly. */
    register long x8_brk asm("x8") = 214;
    register long x0_brk asm("x0") = 0;
    asm volatile("svc #0" : "+r"(x0_brk) : "r"(x8_brk) : "memory");
    char *p0 = (char *)x0_brk;
    x0_brk = (long)p0 + 4096;
    asm volatile("svc #0" : "+r"(x0_brk) : "r"(x8_brk) : "memory");
    char *p1 = (char *)x0_brk;
    OK(p1 == p0 + 4096, "brk grow");
    p0[0] = 0x5a; /* first byte of the grown region (brk itself is invalid) */
    OK(p0[0] == 0x5a, "brk touch");
    x0_brk = 0;
    asm volatile("svc #0" : "+r"(x0_brk) : "r"(x8_brk) : "memory");
    OK((char *)x0_brk == p1, "brk query after grow");

    /* --- mmap anon (+ touch, munmap) --- */
    char *m = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    OK(m != MAP_FAILED, "mmap anon");
    m[0] = 0x77;
    OK(m[0] == 0x77, "mmap touch");
    OK(munmap(m, 8192) == 0, "munmap");

    /* --- writev --- */
    struct iovec iov[2] = { { (void *)"A", 1 }, { (void *)"B", 1 } };
    OK(writev(1, iov, 2) == 2, "writev");

    /* --- ioctl (fake tty state) --- */
    struct termios t;
    OK(ioctl(1, TCGETS, &t) == 0, "ioctl TCGETS");

    /* --- rt_sigaction + kill: handler must see the LINUX signo (10) --- */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    OK(sigaction(SIGUSR1, &sa, 0) == 0, "sigaction");
    OK(kill(getpid(), SIGUSR1) == 0, "kill self");
    OK(got == SIGUSR1, "handler saw SIGUSR1=10");

    if (!fails) {
        static const char ok[] = "linux-probe: all ok\n";
        write(1, ok, sizeof(ok) - 1);
    }
    return fails;
}
