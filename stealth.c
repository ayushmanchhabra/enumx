#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* ── Constants ────────────────────────────────────────────────────────── */
#define DEFAULT_TTL      64
#define DEFAULT_WINDOW   65535
#define SRC_PORT_MIN     1024
#define SRC_PORT_MAX     65535
#define RECV_BUF_SIZE    65536
#define RECV_TIMEOUT_SEC 5
#define MAX_RETRIES      3

/* ── Types ────────────────────────────────────────────────────────────── */
struct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t tcp_len;
};

struct packet {
    struct iphdr  ip;
    struct tcphdr tcp;
};

/* ── Prototypes ───────────────────────────────────────────────────────── */
static uint16_t checksum(const void *data, size_t len);
static void     fill_ip_header(struct iphdr *ip, uint32_t src, uint32_t dst);
static void     fill_syn_header(struct tcphdr *tcp, uint16_t sport, uint16_t dport, uint32_t isn);
static void     fill_rst_header(struct tcphdr *tcp, uint32_t seq);
static void     recompute_tcp_checksum(struct packet *pkt);
static int      open_raw_socket(void);
static int      set_recv_timeout(int sock, int seconds);
static int      send_packet(int sock, struct packet *pkt, const char *tag);
static int      send_rst(int sock, struct packet *orig, uint32_t isn);
static int      wait_for_synack(int sock, uint32_t src_addr, uint32_t dst_addr,
                                 uint16_t sport, uint16_t dport, uint32_t *peer_seq);
static void     usage(const char *prog);

/* ══════════════════════════════════════════════════════════════════════ */

/*
 * Standard Internet checksum (RFC 1071).
 */
static uint16_t checksum(const void *data, size_t len) {
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1)  { sum += *ptr++; len -= 2; }
    if   (len == 1)    sum += *(const uint8_t *)ptr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum;
}

/*
 * Populate an IP header.
 */
static void fill_ip_header(struct iphdr *ip, uint32_t src, uint32_t dst) {
    ip->version  = 4;
    ip->ihl      = sizeof(struct iphdr) / 4;
    ip->tos      = 0;
    ip->tot_len  = htons(sizeof(struct packet));
    ip->id       = htons((uint16_t)(rand() & 0xffff));
    ip->frag_off = htons(IP_DF);
    ip->ttl      = DEFAULT_TTL;
    ip->protocol = IPPROTO_TCP;
    ip->check    = 0;
    ip->saddr    = src;
    ip->daddr    = dst;
}

/*
 * Populate a TCP SYN header.
 */
static void fill_syn_header(struct tcphdr *tcp,
                             uint16_t sport, uint16_t dport,
                             uint32_t isn) {
    memset(tcp, 0, sizeof(*tcp));
    tcp->source  = htons(sport);
    tcp->dest    = htons(dport);
    tcp->seq     = htonl(isn);
    tcp->doff    = sizeof(struct tcphdr) / 4;
    tcp->syn     = 1;
    tcp->window  = htons(DEFAULT_WINDOW);
}

/*
 * Mutate a TCP header into a RST.
 * RFC 793: SEQ = our ISN + 1 (what the server ACK'd).
 */
static void fill_rst_header(struct tcphdr *tcp, uint32_t seq) {
    tcp->seq     = htonl(seq);
    tcp->ack_seq = 0;
    tcp->syn     = 0;
    tcp->ack     = 0;
    tcp->fin     = 0;
    tcp->psh     = 0;
    tcp->urg     = 0;
    tcp->rst     = 1;
    tcp->check   = 0;
}

/*
 * Recompute and store the TCP checksum.
 * Must be called after any change to ip or tcp fields.
 */
static void recompute_tcp_checksum(struct packet *pkt) {
    struct {
        struct pseudo_header ph;
        struct tcphdr        tcp;
    } scratch;

    memset(&scratch, 0, sizeof(scratch));
    scratch.ph.src     = pkt->ip.saddr;
    scratch.ph.dst     = pkt->ip.daddr;
    scratch.ph.zero    = 0;
    scratch.ph.proto   = IPPROTO_TCP;
    scratch.ph.tcp_len = htons(sizeof(struct tcphdr));
    memcpy(&scratch.tcp, &pkt->tcp, sizeof(struct tcphdr));
    scratch.tcp.check  = 0;

    pkt->tcp.check = checksum(&scratch, sizeof(scratch));
}

/*
 * Open a raw IPv4/TCP socket and opt in to supplying our own IP header.
 * Requires CAP_NET_RAW (root).
 */
static int open_raw_socket(void) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket() — needs root / CAP_NET_RAW");
        return -1;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(sock);
        return -1;
    }

    return sock;
}

/*
 * Set a receive timeout so we don't block forever waiting for a SYN-ACK.
 */
static int set_recv_timeout(int sock, int seconds) {
    struct timeval tv = { .tv_sec = seconds, .tv_usec = 0 };
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt(SO_RCVTIMEO)");
        return -1;
    }
    return 0;
}

/*
 * Transmit a raw packet and log what we sent.
 * Log always reads: us -> them.
 */
static int send_packet(int sock, struct packet *pkt, const char *tag) {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = pkt->tcp.dest;
    dest.sin_addr.s_addr = pkt->ip.daddr;

    ssize_t sent = sendto(sock, pkt, sizeof(*pkt), 0,
                          (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        fprintf(stderr, "sendto(%s): %s\n", tag, strerror(errno));
        return -1;
    }

    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pkt->ip.saddr, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &pkt->ip.daddr, dst_str, sizeof(dst_str));

    printf("[>] %-7s  %s:%-5d -> %s:%-5d  seq=%-10u  bytes=%zd\n",
           tag,
           src_str, ntohs(pkt->tcp.source),
           dst_str, ntohs(pkt->tcp.dest),
           ntohl(pkt->tcp.seq),
           sent);
    return 0;
}

/*
 * Build and send a RST from scratch using the original SYN packet as
 * reference — same direction (us -> server), so the log always reads cleanly.
 */
static int send_rst(int sock, struct packet *orig, uint32_t isn) {
    struct packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    /* same src/dst as the SYN — RST goes us -> server */
    fill_ip_header(&pkt.ip, orig->ip.saddr, orig->ip.daddr);

    fill_rst_header(&pkt.tcp, isn + 1);
    pkt.tcp.source = orig->tcp.source;          /* our sport                  */
    pkt.tcp.dest   = orig->tcp.dest;            /* server dport               */
    pkt.tcp.doff   = sizeof(struct tcphdr) / 4;

    recompute_tcp_checksum(&pkt);
    return send_packet(sock, &pkt, "RST");
}

/*
 * Block on the raw socket until we receive a TCP segment matching
 * our 4-tuple, then validate it is a SYN-ACK.
 *
 * Returns  0 on SYN-ACK  (*peer_seq set to server's ISN)
 *         -1 on timeout, RST, or hard error
 */
static int wait_for_synack(int sock,
                            uint32_t src_addr, uint32_t dst_addr,
                            uint16_t sport,    uint16_t dport,
                            uint32_t *peer_seq) {
    char buf[RECV_BUF_SIZE];

    printf("[*] Waiting for SYN-ACK (timeout %ds)...\n", RECV_TIMEOUT_SEC);

    while (1) {
        ssize_t n = recv(sock, buf, sizeof(buf), 0);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                fprintf(stderr, "[-] Timeout — no SYN-ACK received\n");
            else
                perror("recv");
            return -1;
        }

        if ((size_t)n < sizeof(struct iphdr) + sizeof(struct tcphdr))
            continue;

        const struct iphdr *ip = (const struct iphdr *) buf;

        size_t ip_hdr_len = (size_t)ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) ||
            (size_t)n  < ip_hdr_len + sizeof(struct tcphdr))
            continue;

        const struct tcphdr *tcp = (const struct tcphdr *)(buf + ip_hdr_len);

        if (ip->protocol       != IPPROTO_TCP) continue;
        if (ip->saddr          != dst_addr)    continue;
        if (ip->daddr          != src_addr)    continue;
        if (ntohs(tcp->source) != dport)       continue;
        if (ntohs(tcp->dest)   != sport)       continue;

        if (tcp->rst) {
            printf("[-] RST received — port %d is CLOSED\n", dport);
            return -1;
        }

        if (tcp->syn && tcp->ack) {
            *peer_seq = ntohl(tcp->seq);

            char src_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip->saddr, src_str, sizeof(src_str));

            printf("[<] %-7s  %s:%-5d -> *:%-5d    seq=%-10u  ack=%u\n",
                   "SYN-ACK",
                   src_str, dport,
                   sport,
                   *peer_seq,
                   ntohl(tcp->ack_seq));
            return 0;
        }
    }
}

/* ── Usage ────────────────────────────────────────────────────────────── */
static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s <dst_ip> <dst_port> <src_ip>\n\n"
            "  Performs a TCP half-open (stealth) scan:\n"
            "    SYN     ->  target\n"
            "    SYN-ACK <-  target  (port open)\n"
            "    RST     ->  target  (tear down without completing handshake)\n\n"
            "  src_ip  Your real IP address (needed to receive the SYN-ACK).\n"
            "  Requires root / CAP_NET_RAW.\n",
            prog);
}

/* ══════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }

    const char *dst_ip = argv[1];
    uint16_t    dport  = (uint16_t)atoi(argv[2]);
    const char *src_ip = argv[3];

    if (dport == 0) {
        fprintf(stderr, "[-] Invalid port: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    uint32_t dst_addr = inet_addr(dst_ip);
    uint32_t src_addr = inet_addr(src_ip);
    if (dst_addr == INADDR_NONE) {
        fprintf(stderr, "[-] Invalid destination IP: %s\n", dst_ip);
        return EXIT_FAILURE;
    }
    if (src_addr == INADDR_NONE) {
        fprintf(stderr, "[-] Invalid source IP: %s\n", src_ip);
        return EXIT_FAILURE;
    }

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    uint16_t sport = (uint16_t)(SRC_PORT_MIN +
                     (unsigned)rand() % (SRC_PORT_MAX - SRC_PORT_MIN + 1));
    uint32_t isn   = (uint32_t)rand();

    int sock = open_raw_socket();
    if (sock < 0) return EXIT_FAILURE;

    if (set_recv_timeout(sock, RECV_TIMEOUT_SEC) < 0) {
        close(sock);
        return EXIT_FAILURE;
    }

    struct packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    fill_ip_header (&pkt.ip,  src_addr, dst_addr);
    fill_syn_header(&pkt.tcp, sport, dport, isn);
    recompute_tcp_checksum(&pkt);

    int      rc       = EXIT_FAILURE;
    uint32_t peer_seq = 0;

    for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        if (attempt > 1)
            printf("[*] Retrying SYN (%d/%d)...\n", attempt, MAX_RETRIES);

        if (send_packet(sock, &pkt, "SYN") < 0)
            goto done;

        if (wait_for_synack(sock, src_addr, dst_addr,
                            sport, dport, &peer_seq) == 0)
            goto send_reset;

        if (errno != EAGAIN && errno != EWOULDBLOCK)
            goto done;
    }

    fprintf(stderr, "[-] No SYN-ACK after %d attempts — port may be filtered\n",
            MAX_RETRIES);
    goto done;

send_reset:
    if (send_rst(sock, &pkt, isn) < 0)
        goto done;

    printf("[+] Port %d is OPEN  (half-open scan complete — connection reset)\n",
           dport);
    rc = EXIT_SUCCESS;

done:
    close(sock);
    return rc;
}
