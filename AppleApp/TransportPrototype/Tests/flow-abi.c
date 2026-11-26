// Exercises the same file descriptor API that the macOS system extension uses.
#include "CoreIPSec.h"
#include <arpa/inet.h>
#include <assert.h>
#include <net/if.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct fixture { int socket; int udp; };

static void *echo_peer(void *opaque) {
    struct fixture *f = opaque;
    unsigned char packet[32];
    if (f->udp) {
        struct sockaddr_storage client;
        socklen_t size = sizeof client;
        ssize_t count = recvfrom(f->socket, packet, sizeof packet, 0, (struct sockaddr *)&client, &size);
        assert(count == 4);
        assert(sendto(f->socket, packet, count, 0, (struct sockaddr *)&client, size) == count);
    } else {
        int peer = accept(f->socket, NULL, NULL);
        assert(peer >= 0);
        assert(recv(peer, packet, 4, MSG_WAITALL) == 4);
        assert(send(peer, packet, 4, 0) == 4);
        close(peer);
    }
    return NULL;
}

int main(void) {
    char configuration[160];
    snprintf(configuration, sizeof configuration, "{\"interface\":\"lo0\",\"index\":%u,\"ipv4\":\"127.0.0.1\"}", if_nametoindex("lo0"));
    assert(CRouteOpen("{}", "127.0.0.1", 1, 0) == -1);
    assert(CRouteOpen(configuration, "does-not-resolve.invalid", 1, 0) == -1);
    for (int udp = 0; udp <= 1; ++udp) {
        struct fixture f = { socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0), udp };
        struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
        assert(f.socket >= 0 && bind(f.socket, (struct sockaddr *)&address, sizeof address) == 0);
        if (!udp) assert(listen(f.socket, 1) == 0);
        socklen_t size = sizeof address;
        assert(getsockname(f.socket, (struct sockaddr *)&address, &size) == 0);
        pthread_t thread;
        assert(pthread_create(&thread, NULL, echo_peer, &f) == 0);
        int fd = CRouteOpen(configuration, "127.0.0.1", ntohs(address.sin_port), udp);
        assert(fd >= 0);
        struct timeval timeout = { .tv_sec = 4 };
        assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) == 0);
        unsigned char frame[] = { 0, 4, 'p', 'i', 'n', 'g' }, reply[sizeof frame] = {0};
        unsigned char *payload = udp ? frame : frame + 2;
        size_t length = udp ? sizeof frame : sizeof frame - 2;
        assert(write(fd, payload, length) == (ssize_t)length);
        assert(recv(fd, reply, length, MSG_WAITALL) == (ssize_t)length);
        assert(memcmp(payload, reply, length) == 0);
        close(fd);
        assert(pthread_join(thread, NULL) == 0);
        close(f.socket);
    }
    puts("Transparent flow C ABI verified on loopback TCP and UDP");
}
