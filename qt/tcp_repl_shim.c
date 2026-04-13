/* tcp_repl_shim.c — Minimal TCP server helpers for wafter REPL
 *
 * Exposes simple functions that avoid struct marshaling complexity
 * when calling from Chez Scheme FFI.
 *
 * Build:
 *   gcc -shared -fPIC -O2 -o tcp_repl_shim.so qt/tcp_repl_shim.c
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* Create server socket, bind to port, start listening.
   Pass port=0 to let the OS pick an available port.
   Returns fd on success, -1 on error. */
int tcp_server_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* 127.0.0.1 only */

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 8) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/* Set fd to non-blocking mode.  Returns 0 on success, -1 on error. */
int tcp_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Accept a connection.  Blocks until a client connects.
   Returns client fd, or -1 on error (including EAGAIN for non-blocking). */
int tcp_accept_conn(int server_fd) {
    return accept(server_fd, NULL, NULL);
}

/* Return the port number the server socket is bound to.
   Useful when you passed port=0 to tcp_server_socket(). */
int tcp_get_bound_port(int fd) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr*)&addr, &len) < 0) return -1;
    return (int)ntohs(addr.sin_port);
}

/* Close a file descriptor. */
int tcp_close_fd(int fd) {
    return close(fd);
}
