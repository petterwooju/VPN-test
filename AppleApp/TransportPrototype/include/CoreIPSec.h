#ifndef COREA_VPN_IPSEC_H
#define COREA_VPN_IPSEC_H
#include <stdint.h>
#define COREA_PROXY_BRIDGE 1
#ifdef __cplusplus
extern "C" {
#endif
// Handles are process-local. One writer and one reader may call concurrently.
// Connect/Addresses return 0 on success. Negative values are failures.
// Connect consumes Keychain credentials in process and never logs their value.
uint64_t CVPNCreate(void);
int CVPNConnect(uint64_t handle, char *address, char *remoteHost, char *username, char *password, int timeoutMs);
int CVPNAddresses(uint64_t handle, char *ipv4, int v4cap, char *ipv6, int v6cap);
// One IP datagram per call. Read returns 0 on timeout and -1 when closed.
int CVPNRead(uint64_t handle, void *buffer, int cap, int timeoutMs);
int CVPNWrite(uint64_t handle, void *buffer, int size);
void CVPNClose(uint64_t handle);
// Open a connected socketpair stream on an explicitly bound route. The caller
// owns the returned descriptor; UDP datagrams use a 2-byte big-endian length.
int CRouteOpen(char *configuration, char *target, int port, int udp);
int CRouteProbe(char *configuration, char *healthURL);
// Each handle represents exactly one selected proxy leaf. configuration is its
// normalized in-process JSON, which includes credentials read from Keychain.
uint64_t CProxyCreate(char *configuration);
int CProxyPreflight(uint64_t handle, int timeoutMs);
int CProxyRead(uint64_t handle, void *buffer, int cap, int timeoutMs);
int CProxyWrite(uint64_t handle, void *buffer, int size);
void CProxyClose(uint64_t handle);
#ifdef __cplusplus
}
#endif
#endif
