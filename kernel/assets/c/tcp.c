/* tihkali N2 TCP probe (Linux/musl): connect through SLIRP to a host
 * listener at 10.0.2.2:18080, send one line, verify the reply.
 * Contract like linux-probe: FAIL: lines + exit code = failed checks;
 * "tcp: all ok" on success.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
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

static void fail_errno(const char *tag)
{
    char b[64];
    int i = 0;
    while (tag[i]) {
        b[i] = tag[i];
        i++;
    }
    int e = errno;
    b[i++] = '0' + (e / 100) % 10;
    b[i++] = '0' + (e / 10) % 10;
    b[i++] = '0' + (e % 10);
    b[i++] = '\n';
    write(1, b, i);
}

int main(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    OK(fd >= 0, "socket");

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(18080);
    sa.sin_addr.s_addr = htonl(0x0a000202); /* 10.0.2.2 */

    if (fd >= 0 && connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        static const char f[] = "FAIL: connect\n";
        write(1, f, sizeof(f) - 1);
        fail_errno("tcp: connect errno ");
        fails++;
    }

    static const char msg[] = "hello-tihkali\n";
    OK(write(fd, msg, sizeof msg - 1) == (int)(sizeof msg - 1), "send");

    char buf[64];
    int n = read(fd, buf, sizeof buf - 1);
    OK(n > 0, "recv");
    if (n <= 0) {
        char b[48];
        int i = 0;
        const char *t = "tcp: recv n=";
        while (t[i]) { b[i] = t[i]; i++; }
        int v = n, d[4], k = 0;
        do { d[k++] = '0' + (v % 10); v /= 10; } while (v && k < 4);
        while (k--) b[i++] = d[k];
        b[i++] = ' ';
        b[i++] = 'e';
        b[i++] = '=';
        int e = errno;
        b[i++] = '0' + (e / 100) % 10;
        b[i++] = '0' + (e / 10) % 10;
        b[i++] = '0' + (e % 10);
        b[i++] = '\n';
        write(1, b, i);
    }
    if (n > 0) {
        buf[n] = '\0';
        OK(strcmp(buf, "tihkali-tcp-ok") == 0, "payload");
        write(1, "tcp: got '", 10);
        write(1, buf, n);
        write(1, "'\n", 2);
    }
    close(fd);

    if (!fails) {
        static const char ok[] = "tcp: all ok\n";
        write(1, ok, sizeof(ok) - 1);
    }
    return fails;
}
