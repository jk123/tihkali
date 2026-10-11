/* tihkali Linux-ABI test: static musl binary run through the kernel's
 * Linux personality (svc #0 with the syscall number in x8). */
#include <unistd.h>

int main(void) {
    static const char msg[] = "hello from linux/musl (EL0 via Linux ABI)\n";
    write(1, msg, sizeof msg - 1);
    return 42; /* surfaces as wait4 status 42 through the NetBSD shell */
}
