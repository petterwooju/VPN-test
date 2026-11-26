#ifndef COREA_SPEED_H
#define COREA_SPEED_H

#include <arpa/inet.h>
#include <curl/curl.h>
#include <dns_sd.h>
#include <net/if.h>
#include <pthread.h>
#include <poll.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>

typedef int (*CSCancelled)(void *);
typedef struct {
    CURL *curl;
    struct curl_slist *resolution;
    struct curl_slist *headers;
    char interface[IF_NAMESIZE];
    unsigned int interfaceIndex;
    size_t received, limit;
    int badEncoding;
    CSCancelled cancelled;
    void *context;
} CSLane;

static pthread_once_t csCurlOnce = PTHREAD_ONCE_INIT;
static CURLcode csCurlInitStatus = CURLE_FAILED_INIT;
static inline void csCurlInit(void) { csCurlInitStatus = curl_global_init(CURL_GLOBAL_DEFAULT); }

static inline int csBind(void *opaque, curl_socket_t fd, curlsocktype purpose) {
    CSLane *lane = (CSLane *)opaque;
    if (purpose != CURLSOCKTYPE_IPCXN || if_nametoindex(lane->interface) != lane->interfaceIndex)
        return CURL_SOCKOPT_ERROR;
    return setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &lane->interfaceIndex,
                      sizeof(lane->interfaceIndex)) == 0 ? CURL_SOCKOPT_OK : CURL_SOCKOPT_ERROR;
}

static inline size_t csDiscard(char *data, size_t size, size_t count, void *opaque) {
    CSLane *lane = (CSLane *)opaque;
    size_t bytes = size * count;
    lane->received += bytes;
    if (lane->received > lane->limit) return 0;
    return bytes;
}

static inline size_t csHeader(char *data, size_t size, size_t count, void *opaque) {
    size_t len = size * count;
    const char prefix[] = "content-encoding:";
    if (len >= sizeof(prefix) - 1 && strncasecmp(data, prefix, sizeof(prefix) - 1) == 0) {
        size_t pos = sizeof(prefix) - 1;
        while (pos < len && (data[pos] == ' ' || data[pos] == '\t')) ++pos;
        size_t end = len;
        while (end > pos && (data[end - 1] == '\r' || data[end - 1] == '\n' ||
                             data[end - 1] == ' ' || data[end - 1] == '\t')) --end;
        if (end - pos != 8 || strncasecmp(data + pos, "identity", 8) != 0)
            ((CSLane *)opaque)->badEncoding = 1;
    }
    return len;
}

static inline int csProgress(void *opaque, curl_off_t a, curl_off_t b, curl_off_t c, curl_off_t d) {
    CSLane *lane = (CSLane *)opaque;
    return lane->cancelled(lane->context);
}

static inline void csClose(CSLane *lane) {
    if (lane) {
        if (lane->curl) curl_easy_cleanup(lane->curl);
        curl_slist_free_all(lane->resolution);
        curl_slist_free_all(lane->headers);
        free(lane);
    }
}

static inline CSLane *csOpen(const char *interface, unsigned int index, const char *peer,
                             CSCancelled cancelled, void *context) {
    pthread_once(&csCurlOnce, csCurlInit);
    if (csCurlInitStatus != CURLE_OK || index == 0 || if_nametoindex(interface) != index) return NULL;
    CSLane *lane = (CSLane *)calloc(1, sizeof(CSLane));
    if (!lane) return NULL;
    strlcpy(lane->interface, interface, sizeof(lane->interface));
    lane->interfaceIndex = index;
    lane->cancelled = cancelled;
    lane->context = context;
    char pin[128];
    snprintf(pin, sizeof(pin), "speed.cloudflare.com:443:%s", peer);
    lane->curl = curl_easy_init();
    lane->resolution = curl_slist_append(NULL, pin);
    lane->headers = curl_slist_append(NULL, "Cache-Control: no-cache, no-store");
    if (!lane->curl || !lane->resolution || !lane->headers) { csClose(lane); return NULL; }
    struct curl_slist *headers = curl_slist_append(lane->headers, "Content-Type: application/octet-stream");
    if (!headers) { csClose(lane); return NULL; }
    lane->headers = headers;
#define CS_SET(opt, value) if (curl_easy_setopt(lane->curl, opt, value) != CURLE_OK) { csClose(lane); return NULL; }
    CS_SET(CURLOPT_PROXY, "");
    CS_SET(CURLOPT_RESOLVE, lane->resolution);
    CS_SET(CURLOPT_HTTPHEADER, lane->headers);
    CS_SET(CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    CS_SET(CURLOPT_SOCKOPTFUNCTION, csBind);
    CS_SET(CURLOPT_SOCKOPTDATA, lane);
    CS_SET(CURLOPT_NOSIGNAL, 1L);
    CS_SET(CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    CS_SET(CURLOPT_CONNECTTIMEOUT_MS, 2000L);
    CS_SET(CURLOPT_WRITEFUNCTION, csDiscard);
    CS_SET(CURLOPT_WRITEDATA, lane);
    CS_SET(CURLOPT_HEADERFUNCTION, csHeader);
    CS_SET(CURLOPT_HEADERDATA, lane);
    CS_SET(CURLOPT_XFERINFOFUNCTION, csProgress);
    CS_SET(CURLOPT_XFERINFODATA, lane);
    CS_SET(CURLOPT_NOPROGRESS, 0L);
#undef CS_SET
    return lane;
}

typedef struct {
    size_t bytes;           // Verified bytes used for throughput.
    size_t receivedBytes;   // All payload bytes delivered to the callback, even on failure.
    double responseMS;
    long httpStatus;
    int success, requestSent;
    const char *stage, *errorType, *errorReason;
} CSResult;


static inline CSResult csRequest(CSLane *lane, const char *url, size_t size, const void *payload,
                                 long timeoutMS) {
    CSResult result = {0};
    result.stage = "request";
    result.errorType = "setup";
    result.errorReason = "Could not configure HTTPS request";
    if (timeoutMS < 1 || lane->cancelled(lane->context)) {
        result.errorType = timeoutMS < 1 ? "timeout" : "cancelled";
        result.errorReason = timeoutMS < 1 ? "Measurement deadline reached" : "Cancelled";
        return result;
    }
    lane->received = 0;
    lane->limit = payload ? 4096 : size;
    lane->badEncoding = 0;
    CURL *curl = lane->curl;
    if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeoutMS) != CURLE_OK) return result;
    if (payload) {
        if (curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload) != CURLE_OK ||
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)size) != CURLE_OK) return result;
    } else if (curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L) != CURLE_OK) return result;
    CURLcode status = curl_easy_perform(curl);
    long requestBytes = 0;
    if (curl_easy_getinfo(curl, CURLINFO_REQUEST_SIZE, &requestBytes) == CURLE_OK && requestBytes > 0)
        result.requestSent = 1;
    long http = 0;
    double total = 0, prepared = 0;
    result.receivedBytes = lane->received;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
    result.httpStatus = http;
    result.stage = http ? "body" : result.requestSent ? "response_headers" : "connect";
    if (http && (http < 200 || http >= 300)) {
        result.stage = "response_headers";
        result.errorType = "http_status";
        result.errorReason = "Unexpected HTTP status";
        return result;
    }
    if (lane->badEncoding) {
        result.stage = "response_headers";
        result.errorType = "encoding";
        result.errorReason = "Unexpected content encoding";
        return result;
    }
    if (!payload && lane->received > size) {
        result.stage = "end_validation";
        result.errorType = "length";
        result.errorReason = "Response exceeded requested size";
        return result;
    }
    if (status != CURLE_OK) {
        switch (status) {
            case CURLE_OPERATION_TIMEDOUT: result.errorType = "timeout"; break;
            case CURLE_PARTIAL_FILE: case CURLE_GOT_NOTHING: result.errorType = "early_eof"; break;
            case CURLE_SSL_CONNECT_ERROR: case CURLE_PEER_FAILED_VERIFICATION:
                result.stage = "tls"; result.errorType = "tls"; break;
            default: result.errorType = "curl"; break;
        }
        result.errorReason = curl_easy_strerror(status);
        return result;
    }
    if (!http) {
        result.errorType = "http_status";
        result.errorReason = "Missing HTTPS response status";
        return result;
    }
    if (payload) {
        curl_off_t sent = 0;
        if (curl_easy_getinfo(curl, CURLINFO_SIZE_UPLOAD_T, &sent) != CURLE_OK || sent != (curl_off_t)size)
            return result;
    }
    if (!payload && lane->received != size) {
        result.errorType = "early_eof";
        result.errorReason = "Response ended before requested size";
        return result;
    }
    if (curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total) != CURLE_OK ||
        curl_easy_getinfo(curl, CURLINFO_PRETRANSFER_TIME, &prepared) != CURLE_OK || total < prepared) return result;
    result.bytes = payload ? size : lane->received;
    result.responseMS = (total - prepared) * 1000.0;
    result.success = 1;
    result.stage = "complete";
    result.errorType = result.errorReason = NULL;
    return result;
}

typedef struct { struct in_addr ip; int found; } CSDNSAnswer;
static inline void csAnswer(DNSServiceRef ref, DNSServiceFlags flags, uint32_t index, DNSServiceErrorType error,
                            const char *name, const struct sockaddr *address, uint32_t ttl, void *context) {
    if (!error && (flags & kDNSServiceFlagsAdd) && address && address->sa_family == AF_INET) {
        CSDNSAnswer *answer = (CSDNSAnswer *)context;
        answer->ip = ((const struct sockaddr_in *)address)->sin_addr;
        answer->found = 1;
    }
}

// Bound both cancellation and lookup time before starting TLS, using the Mac's effective DNS.
static inline int csResolve(char *out, size_t capacity, CSCancelled cancelled, void *context) {
    DNSServiceRef ref = NULL;
    CSDNSAnswer answer = {0};
    if (DNSServiceGetAddrInfo(&ref, 0, kDNSServiceInterfaceIndexAny, kDNSServiceProtocol_IPv4,
                              "speed.cloudflare.com", csAnswer, &answer) != kDNSServiceErr_NoError) return 0;
    struct pollfd descriptor = {DNSServiceRefSockFD(ref), POLLIN, 0};
    uint64_t start = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    while (!answer.found && !cancelled(context) && clock_gettime_nsec_np(CLOCK_UPTIME_RAW) - start < 5000000000ULL) {
        int n = poll(&descriptor, 1, 100);
        if (n < 0 || (n > 0 && DNSServiceProcessResult(ref) != kDNSServiceErr_NoError)) break;
    }
    DNSServiceRefDeallocate(ref);
    return answer.found && inet_ntop(AF_INET, &answer.ip, out, (socklen_t)capacity) != NULL;
}
#endif
