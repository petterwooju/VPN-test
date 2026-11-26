#include "CoreIPSec.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static void *blocked_read(void *arg) {
    uint8_t scratch[1500];
    uint64_t handle = *(uint64_t*)arg;
    assert(CVPNRead(handle, scratch, sizeof scratch, 5000) == -1);
    return NULL;
}

int main(void) {
    uint64_t handle = CVPNCreate();
    assert(handle);
    // Invalid identity is rejected locally before credential transmission or any dial.
    assert(CVPNConnect(handle, "203.0.113.1", "example.invalid", "fixture", "fixture", 10) == -2);
    char address4[48], address6[48];
    assert(CVPNAddresses(handle, address4, sizeof address4, address6, sizeof address6) == -1);
    unsigned char packet[10] = {0};
    assert(CVPNWrite(handle, packet, sizeof packet) == -2);
    pthread_t reader;
    assert(pthread_create(&reader, NULL, blocked_read, &handle) == 0);
    usleep(10000);
    CVPNClose(handle);
    assert(CProxyCreate("{}") == 0);
    uint64_t leaf = CProxyCreate("{\"name\":\"fixture\",\"type\":\"ss\",\"server\":\"203.0.113.1\",\"port\":42000,\"cipher\":\"aes-128-gcm\",\"password\":\"fixture\"}");
    assert(leaf);
    // No route can be claimed or used until this particular leaf passes a real external test.
    assert(CProxyWrite(leaf, packet, sizeof packet) == -4);
    assert(CProxyRead(leaf, packet, sizeof packet, 10) == -4);
    CProxyClose(leaf);
    CProxyClose(leaf);
    assert(pthread_join(reader, NULL) == 0);
    CVPNClose(handle);
    puts("CoreIPSec C ABI: validation, cancel/read wakeup and idempotent close passed");
    return 0;
}
