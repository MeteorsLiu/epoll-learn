#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/if_tun.h>

#define _GNU_SOURCE 
#include <fcntl.h>

volatile sig_atomic_t exit_signal_received;
typedef struct epoll_context* Ctx;
struct epoll_context {
    struct epoll_event events[2];
    int epollfd;
};

int tun_create(char if_name[IFNAMSIZ], const char *wanted_name)
{
    struct ifreq ifr;
    int          fd;
    int          err;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "tun module not present. See https://sk.tl/2RdReigK\n");
        return -1;
    }
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", wanted_name == NULL ? "" : wanted_name);
    if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    snprintf(if_name, IFNAMSIZ, "%s", ifr.ifr_name);
    return fd;
}

static int tcp_listener(const char *address, const char *port)
{
    struct addrinfo hints, *res;
    int             eai, err;
    int             listen_fd;
    int             backlog = 1;

    memset(&hints, 0, sizeof hints);
    hints.ai_flags    = AI_PASSIVE;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_addr     = NULL;
    if ((eai = getaddrinfo(address, port, &hints, &res)) != 0 ||
        (res->ai_family != AF_INET && res->ai_family != AF_INET6)) {
        fprintf(stderr, "Unable to create the listening socket: [%s]\n", gai_strerror(eai));
        errno = EINVAL;
        return -1;
    }
    if ((listen_fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP)) == -1 ||
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (char *) (int[]){ 1 }, sizeof(int)) != 0) {
        err = errno;
        (void) close(listen_fd);
        freeaddrinfo(res);
        errno = err;
        return -1;
    }

    printf("Listening to %s:%s\n", address == NULL ? "*" : address, port);
    if (bind(listen_fd, (struct sockaddr *) res->ai_addr, (socklen_t) res->ai_addrlen) != 0 ||
        listen(listen_fd, backlog) != 0) {
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    return listen_fd;
}
int event_add(Ctx epoll, int fd) 
{
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    if (epoll_ctl(epoll->epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        perror("epoll_ctl: listen_sock");
        return -1;
    }
}

static void signal_handler(int sig)
{
    signal(sig, SIG_DFL);
    exit_signal_received = 1;
}
int main(void) {
    char if_name[IFNAMSIZ];
    unsigned char buf[1500];
    int nfds;

    struct epoll_context e = { .epollfd = epoll_create1(0) };

    if (e.epollfd == -1) {
        goto exit;
    }
    int fd = tcp_listener("127.0.0.1", "9999");
   
    int tunfd = tun_create(if_name, "tun-0");
    memset(buf, 0, sizeof(buf));
    event_add(&e, fd);
    event_add(&e, tunfd);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    while (exit_signal_received != 1) {
        nfds = epoll_wait(e.epollfd, e.events, 2, -1);
        if (nfds == -1) break;
        for (int n = 0; n < nfds; ++n) {
            if (e.events[n].data.fd == fd) {
                printf("listen in\n");
            } else if (e.events[n].data.fd == tunfd) {
                ssize_t readnb;
                while ((readnb = read(tunfd, buf, 1500)) < (ssize_t) 0 && errno == EINTR && !exit_signal_received);
                printf("Read: %ld\n", readnb);
            }
        }
    }
    close(e.epollfd);
exit:
    return 0;
}
