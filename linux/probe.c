/* tihkali Linux-ABI depth probe: exercises the full deferred syscall set
 * through musl wrappers. Exit code = number of failed checks (0 = pass). */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
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

static volatile int chld_got;

static void chandler(int s) {
    chld_got = s;
}

/* Re-entrant kill from inside the handler: with the delivered signal
 * blocked during handler execution (POSIX default), the re-kill stays
 * pending until sigreturn — the handler must run a SECOND time
 * sequentially, never nested. */
static volatile int hcnt, hdepth, hnested;

static void rh(int s) {
    if (hdepth) {
        hnested = 1;
    }
    hdepth++;
    if (hcnt++ == 0) {
        kill(getpid(), s);
    }
    hdepth--;
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

    /* --- M19a: signals hardening ---
     * SIGPIPE/EPIPE, wait4 signo ABI translation, EL0 fault -> process
     * death, SIG_IGN across exec, SIGCHLD delivery, group kill, and
     * block-during-handler (no nested re-entry). */

    struct sigaction dfl, ig2;
    memset(&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    memset(&ig2, 0, sizeof ig2);
    ig2.sa_handler = SIG_IGN;

    /* EPIPE + SIGPIPE(ignored) on a readerless pipe. */
    int q[2];
    pipe(q);
    close(q[0]);
    OK(sigaction(SIGPIPE, &ig2, 0) == 0, "sigaction SIGPIPE IGN");
    n = write(q[1], "x", 1);
    OK(n == -1 && errno == EPIPE, "EPIPE on readerless pipe");
    close(q[1]);

    /* Default SIGPIPE disposition: writer dies with SIGPIPE (13). */
    pid_t pb = fork();
    if (pb == 0) {
        sigaction(SIGPIPE, &dfl, 0);
        int q2[2];
        pipe(q2);
        close(q2[0]);
        write(q2[1], "x", 1); /* no readers: EPIPE + SIGPIPE -> die */
        _exit(1);
    }
    int st2 = 0;
    waitpid(pb, &st2, 0);
    OK(WIFSIGNALED(st2) && WTERMSIG(st2) == SIGPIPE, "SIGPIPE default death");

    /* wait4 signo translation: child dies with USR1 (canonical 30);
     * a Linux waiter must see Linux USR1 = 10, not 30. */
    pid_t pu = fork();
    if (pu == 0) {
        sigaction(SIGUSR1, &dfl, 0); /* undo inherited handler */
        kill(getpid(), SIGUSR1);
        _exit(1);
    }
    waitpid(pu, &st2, 0);
    OK(WIFSIGNALED(st2) && WTERMSIG(st2) == SIGUSR1, "wait4 USR1 -> Linux 10");

    /* EL0 faults must kill the process, not the kernel. */
    pid_t pf = fork();
    if (pf == 0) {
        *(volatile int *)0x1234 = 1; /* data abort outside user VA */
        _exit(1);
    }
    waitpid(pf, &st2, 0);
    OK(WIFSIGNALED(st2) && WTERMSIG(st2) == SIGSEGV, "null deref -> SIGSEGV");

    pid_t pi = fork();
    if (pi == 0) {
        void (*volatile boom)(void) = (void (*)(void))0;
        boom(); /* insn fetch at 0 */
        _exit(1);
    }
    waitpid(pi, &st2, 0);
    OK(WIFSIGNALED(st2) && WTERMSIG(st2) == SIGSEGV, "jump to 0 -> SIGSEGV");

    /* SIG_IGN must survive exec (POSIX): child ignores USR2, execs
     * busybox sh which kills itself with USR2 and exits 42. */
    pid_t pe = fork();
    if (pe == 0) {
        sigaction(SIGUSR2, &ig2, 0);
        char *av[] = { "busybox", "sh", "-c", "kill -USR2 $$; exit 42", 0 };
        execve("/bin/busybox", av, 0);
        _exit(99);
    }
    waitpid(pe, &st2, 0);
    OK(WIFEXITED(st2) && WEXITSTATUS(st2) == 42, "SIG_IGN survives exec");

    /* SIGCHLD with a handler must fire when a child exits. */
    struct sigaction cs;
    memset(&cs, 0, sizeof cs);
    cs.sa_handler = chandler;
    OK(sigaction(SIGCHLD, &cs, 0) == 0, "sigaction SIGCHLD");
    pid_t pc = fork();
    if (pc == 0) {
        _exit(7);
    }
    waitpid(pc, &st2, 0);
    OK(WIFEXITED(st2) && WEXITSTATUS(st2) == 7, "CHLD child status");
    OK(chld_got == SIGCHLD, "SIGCHLD handler ran");

    /* kill(-pgid): child moves to its own group, parent signals it. */
    int sp[2];
    pipe(sp);
    pid_t pg = fork();
    if (pg == 0) {
        close(sp[0]);
        if (setpgid(0, 0) != 0) {
            _exit(90);
        }
        write(sp[1], "x", 1);
        for (;;) {
            pause();
        }
    }
    close(sp[1]);
    char gb;
    read(sp[0], &gb, 1); /* blocks until child has setpgid'd */
    close(sp[0]);
    kill(-(int)pg, SIGKILL);
    waitpid(pg, &st2, 0);
    OK(WIFSIGNALED(st2) && WTERMSIG(st2) == SIGKILL, "kill(-pgid) group kill");

    /* block-during-handler: no nested re-entry. */
    struct sigaction rs;
    memset(&rs, 0, sizeof rs);
    rs.sa_handler = rh;
    hcnt = hdepth = hnested = 0;
    OK(sigaction(SIGUSR1, &rs, 0) == 0, "sigaction re-entrant test");
    kill(getpid(), SIGUSR1);
    OK(hcnt == 2, "re-kill delivered after handler returns");
    OK(!hnested, "same signal blocked during handler (no nesting)");

    if (!fails) {
        static const char ok[] = "linux-probe: all ok\n";
        write(1, ok, sizeof(ok) - 1);
    }
    return fails;
}
