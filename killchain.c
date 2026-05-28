/*
 * killchain.c — TCP half-open (SYN) scanner with ICMP host discovery
 *
 * Phase 1: ICMP ping sweep — discovers live hosts in the subnet.
 * Phase 2: SYN scan       — scans ports only on live hosts.
 *
 * Usage:
 *   sudo ./killchain <dst_ip|cidr> [output.csv] [--src <ip>] [--port <N>]
 *                                  [--timeout <secs>] [--ping-timeout <secs>]
 *
 * Examples:
 *   sudo ./killchain 10.0.0.1
 *   sudo ./killchain 10.0.0.0/24
 *   sudo ./killchain 192.168.1.0/24 out.csv --port 80 --timeout 3
 *
 * Requires root / CAP_NET_RAW.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ── Tunables ─────────────────────────────────────────────────────────── */
#define DEFAULT_TTL 64
#define DEFAULT_WINDOW 65535
#define SRC_PORT_FIXED 60000
#define RECV_BUF_SIZE 65536
#define DRAIN_SECS 5
#define PING_TIMEOUT_SECS 2
#define SEND_BATCH_US 500
#define BATCH_SIZE 128

/* ── Limits ───────────────────────────────────────────────────────────── */
#define PORT_MAX 65535
#define SUBNET_HOST_MAX 65536 /* max hosts: /16 */

/* ── Host table ───────────────────────────────────────────────────────── */
typedef enum { ST_UNKNOWN = 0, ST_OPEN, ST_CLOSED, ST_FILTERED } port_state_t;

typedef struct {
  uint32_t addr; /* network byte order                */
  int alive;     /* 1 = responded to ping             */
  port_state_t state[PORT_MAX + 1];
  struct {
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t window;
  } detail[PORT_MAX + 1];
} host_entry_t;

static host_entry_t *g_hosts = NULL;
static int g_host_count = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* ── CSV ──────────────────────────────────────────────────────────────── */
static FILE *g_csv;

static void csv_field(FILE *f, const char *s) {
  (void)fputc('"', f);
  for (; *s; s++) {
    if (*s == '"') {
      (void)fputc('"', f);
      (void)fputc('"', f);
    } else if (*s == '\n') {
      (void)fputc('\\', f);
      (void)fputc('n', f);
    } else if (*s == '\r') {
      /* skip */
    } else {
      (void)fputc(*s, f);
    }
  }
  (void)fputc('"', f);
}

static void csv_row(const char *host, int port, const char *output) {
  if (!g_csv)
    return;
  csv_field(g_csv, host);
  (void)fprintf(g_csv, ",%d,", port);
  csv_field(g_csv, output);
  (void)fputc('\n', g_csv);
  (void)fflush(g_csv);
}

/* ── Structs ──────────────────────────────────────────────────────────── */
struct pseudo_header {
  uint32_t src, dst;
  uint8_t zero, proto;
  uint16_t tcp_len;
};

struct tcp_packet {
  struct iphdr ip;
  struct tcphdr tcp;
};

struct icmp_packet {
  struct icmphdr icmp;
  uint8_t payload[8]; /* embed dst addr so we can match replies */
};

/* recv_args is shared between ping receiver and SYN receiver */
struct recv_args {
  int sock;
  uint32_t src_addr;
  uint16_t sport; /* used by SYN receiver only */
  volatile int *done;
  int drain_secs;
};

/* ── strtol helper ────────────────────────────────────────────────────── */
static long xstrtol(const char *s, int *ok) {
  char *end;
  errno = 0;
  long v = strtol(s, &end, 10);
  *ok = (errno == 0 && end != s && *end == '\0');
  return v;
}

/* ── CIDR parser ──────────────────────────────────────────────────────── */
static int parse_cidr(const char *arg, uint32_t *base_out, int *count_out,
                      char *errbuf, size_t errbuf_len) {
  char buf[64];
  if (strlen(arg) >= sizeof(buf)) {
    (void)snprintf(errbuf, errbuf_len, "target too long");
    return -1;
  }
  (void)snprintf(buf, sizeof(buf), "%s", arg);

  char *slash = strchr(buf, '/');
  int prefix;

  if (!slash) {
    prefix = 32;
  } else {
    *slash = '\0';
    int ok;
    long pv = xstrtol(slash + 1, &ok);
    if (!ok || pv < 0 || pv > 32) {
      (void)snprintf(errbuf, errbuf_len, "invalid prefix length '%s'",
                     slash + 1);
      return -1;
    }
    prefix = (int)pv;
  }

  if (prefix == 0) {
    (void)snprintf(errbuf, errbuf_len, "/0 (entire internet) not supported");
    return -1;
  }
  if (prefix < 16) {
    (void)snprintf(errbuf, errbuf_len,
                   "/%d would require >65536 hosts; minimum supported is /16",
                   prefix);
    return -1;
  }

  struct in_addr ia;
  if (inet_pton(AF_INET, buf, &ia) != 1) {
    (void)snprintf(errbuf, errbuf_len, "invalid IPv4 address '%s'", buf);
    return -1;
  }

  uint32_t addr = ntohl(ia.s_addr);
  uint32_t mask = (~0u << (32 - prefix));
  uint32_t network = addr & mask;

  if (addr != network && prefix != 32) {
    char net_str[INET_ADDRSTRLEN];
    struct in_addr na;
    na.s_addr = htonl(network);
    inet_ntop(AF_INET, &na, net_str, sizeof(net_str));
    (void)fprintf(stderr, "[!] Host bits set in '%s'; using network %s/%d\n",
                  arg, net_str, prefix);
  }

  int total = 1 << (32 - prefix);
  uint32_t first, last_excl;

  if (prefix == 32) {
    first = network;
    last_excl = network + 1;
  } else if (prefix == 31) {
    first = network;
    last_excl = network + 2;
  } else {
    first = network + 1;
    last_excl = network + (uint32_t)total - 1;
  }

  int count = (int)(last_excl - first);
  if (count <= 0) {
    (void)snprintf(errbuf, errbuf_len, "subnet /%d yields no scannable hosts",
                   prefix);
    return -1;
  }
  if (count > SUBNET_HOST_MAX) {
    (void)snprintf(errbuf, errbuf_len,
                   "subnet yields %d hosts, exceeds limit of %d", count,
                   SUBNET_HOST_MAX);
    return -1;
  }

  *base_out = first;
  *count_out = count;
  return 0;
}

/* ── Auto-detect source IP ────────────────────────────────────────────── */
static int get_local_ip(const char *dst_ip, char *out, size_t out_len) {
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    return -1;

  struct sockaddr_in dst = {
      .sin_family = AF_INET,
      .sin_port = htons(80),
      .sin_addr.s_addr = inet_addr(dst_ip),
  };
  if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
    close(sock);
    return -1;
  }

  struct sockaddr_in src;
  socklen_t len = sizeof(src);
  if (getsockname(sock, (struct sockaddr *)&src, &len) < 0) {
    close(sock);
    return -1;
  }

  close(sock);
  inet_ntop(AF_INET, &src.sin_addr, out, out_len);
  return 0;
}

/* ── Checksum ─────────────────────────────────────────────────────────── */
static uint16_t checksum(const void *data, size_t len) {
  const uint16_t *ptr = (const uint16_t *)data;
  uint32_t sum = 0;
  while (len > 1) {
    sum += *ptr++;
    len -= 2;
  }
  if (len == 1)
    sum += *(const uint8_t *)ptr;
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  return (uint16_t)~sum;
}

/* ── Raw socket helpers ───────────────────────────────────────────────── */
static int open_raw_tcp_socket(void) {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sock < 0) {
    perror("socket TCP (needs root/CAP_NET_RAW)");
    return -1;
  }
  int one = 1;
  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
    perror("setsockopt IP_HDRINCL");
    close(sock);
    return -1;
  }
  return sock;
}

static int open_raw_icmp_socket(void) {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock < 0) {
    perror("socket ICMP (needs root/CAP_NET_RAW)");
    return -1;
  }
  /* Do NOT set IP_HDRINCL for ICMP — the kernel builds the IP header
     automatically for IPPROTO_ICMP raw sockets.  Setting it causes the
     kernel to treat our ICMP header as a double IP header and drop the
     packet silently.                                                    */
  return sock;
}

/* ── Packet builders ──────────────────────────────────────────────────── */
static void fill_ip(struct iphdr *ip, uint32_t src, uint32_t dst, uint8_t proto,
                    uint16_t total_len) {
  ip->version = 4;
  ip->ihl = sizeof(struct iphdr) / 4;
  ip->tot_len = htons(total_len);
  ip->id = htons((uint16_t)(arc4random() & 0xffff));
  ip->frag_off = htons(IP_DF);
  ip->ttl = DEFAULT_TTL;
  ip->protocol = proto;
  ip->saddr = src;
  ip->daddr = dst;
}

static void make_icmp_echo(struct icmp_packet *pkt, uint32_t dst, uint16_t id) {
  memset(pkt, 0, sizeof(*pkt));
  pkt->icmp.type = ICMP_ECHO;
  pkt->icmp.code = 0;
  pkt->icmp.un.echo.id = htons(id);
  pkt->icmp.un.echo.sequence = htons(1);
  memcpy(pkt->payload, &dst, sizeof(dst));
  pkt->icmp.checksum = checksum(pkt, sizeof(*pkt));
}

static void tcp_checksum(struct tcp_packet *pkt) {
  struct {
    struct pseudo_header ph;
    struct tcphdr tcp;
  } s;
  memset(&s, 0, sizeof(s));
  s.ph.src = pkt->ip.saddr;
  s.ph.dst = pkt->ip.daddr;
  s.ph.proto = IPPROTO_TCP;
  s.ph.tcp_len = htons(sizeof(struct tcphdr));
  memcpy(&s.tcp, &pkt->tcp, sizeof(struct tcphdr));
  s.tcp.check = 0;
  pkt->tcp.check = checksum(&s, sizeof(s));
}

static void make_syn(struct tcp_packet *pkt, uint32_t src, uint32_t dst,
                     uint16_t sport, uint16_t dport) {
  memset(pkt, 0, sizeof(*pkt));
  fill_ip(&pkt->ip, src, dst, IPPROTO_TCP, (uint16_t)sizeof(struct tcp_packet));
  pkt->tcp.source = htons(sport);
  pkt->tcp.dest = htons(dport);
  pkt->tcp.seq = htonl(arc4random());
  pkt->tcp.doff = sizeof(struct tcphdr) / 4;
  pkt->tcp.syn = 1;
  pkt->tcp.window = htons(DEFAULT_WINDOW);
  tcp_checksum(pkt);
}

static void make_rst(struct tcp_packet *pkt, uint32_t src, uint32_t dst,
                     uint16_t sport, uint16_t dport, uint32_t seq) {
  memset(pkt, 0, sizeof(*pkt));
  fill_ip(&pkt->ip, src, dst, IPPROTO_TCP, (uint16_t)sizeof(struct tcp_packet));
  pkt->tcp.source = htons(sport);
  pkt->tcp.dest = htons(dport);
  pkt->tcp.seq = htonl(seq);
  pkt->tcp.doff = sizeof(struct tcphdr) / 4;
  pkt->tcp.rst = 1;
  tcp_checksum(pkt);
}

static int send_raw_to(int sock, void *pkt, size_t pkt_len, uint32_t dst_addr) {
  struct sockaddr_in dst = {
      .sin_family = AF_INET,
      .sin_addr.s_addr = dst_addr,
  };
  return (int)sendto(sock, pkt, pkt_len, 0, (struct sockaddr *)&dst,
                     sizeof(dst));
}

/* ICMP send — no IP_HDRINCL, kernel fills IP header */
static int send_icmp_to(int sock, struct icmp_packet *pkt, uint32_t dst_addr) {
  struct sockaddr_in dst = {
      .sin_family = AF_INET,
      .sin_addr.s_addr = dst_addr,
  };
  return (int)sendto(sock, pkt, sizeof(*pkt), 0, (struct sockaddr *)&dst,
                     sizeof(dst));
}

/* ── Host table helpers ───────────────────────────────────────────────── */
static host_entry_t *find_host(uint32_t addr_net) {
  for (int i = 0; i < g_host_count; i++)
    if (g_hosts[i].addr == addr_net)
      return &g_hosts[i];
  return NULL;
}

static int count_alive(void) {
  int n = 0;
  for (int i = 0; i < g_host_count; i++)
    if (g_hosts[i].alive)
      n++;
  return n;
}

/* ══════════════════════════════════════════════════════════════════════
 * Phase 1 — ICMP ping sweep
 * ══════════════════════════════════════════════════════════════════════ */

/* Receiver thread for ICMP echo replies */
static void *ping_receiver(void *arg) {
  struct recv_args *a = (struct recv_args *)arg;
  char buf[RECV_BUF_SIZE];
  time_t deadline = 0;

  while (1) {
    if (*a->done && deadline == 0)
      deadline = time(NULL) + a->drain_secs;
    if (deadline && time(NULL) >= deadline)
      break;

    struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
    setsockopt(a->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t n = recv(a->sock, buf, sizeof(buf), 0);
    if (n < 0)
      continue;

    /* Raw ICMP socket without IP_HDRINCL still delivers the full packet
       including the IP header on Linux — parse it normally.             */
    if ((size_t)n < sizeof(struct iphdr) + sizeof(struct icmphdr))
      continue;

    const struct iphdr *ip = (const struct iphdr *)buf;
    size_t ihl = (size_t)ip->ihl * 4;
    if ((size_t)n < ihl + sizeof(struct icmphdr))
      continue;
    if (ip->protocol != IPPROTO_ICMP)
      continue;

    /* Only replies destined for us */
    if (ip->daddr != a->src_addr)
      continue;

    const struct icmphdr *icmp = (const struct icmphdr *)(buf + ihl);
    if (icmp->type != ICMP_ECHOREPLY)
      continue;

    host_entry_t *h = find_host(ip->saddr);
    if (!h)
      continue;

    pthread_mutex_lock(&g_mu);
    if (!h->alive) {
      h->alive = 1;
      char s[INET_ADDRSTRLEN];
      struct in_addr ia;
      ia.s_addr = ip->saddr;
      inet_ntop(AF_INET, &ia, s, sizeof(s));
      printf("[+] HOST UP  %s\n", s);
    }
    pthread_mutex_unlock(&g_mu);
  }
  return NULL;
}

/*
 * Sends ICMP echo requests to all hosts, waits ping_timeout seconds,
 * marks responding hosts alive.  Returns number of live hosts found.
 */
static int ping_sweep(uint32_t src_addr, int ping_timeout) {
  int send_sock = open_raw_icmp_socket();
  int recv_sock = open_raw_icmp_socket();
  if (send_sock < 0 || recv_sock < 0) {
    if (send_sock >= 0)
      close(send_sock);
    if (recv_sock >= 0)
      close(recv_sock);
    return -1;
  }

  volatile int done = 0;
  struct recv_args ra = {
      .sock = recv_sock,
      .src_addr = src_addr,
      .done = &done,
      .drain_secs = ping_timeout,
  };

  pthread_t tid;
  pthread_create(&tid, NULL, ping_receiver, &ra);

  uint16_t ping_id = (uint16_t)(arc4random() & 0xffff);

  int count = 0;
  for (int i = 0; i < g_host_count; i++) {
    if (g_hosts[i].alive)
      continue; /* skip self — already marked alive */
    struct icmp_packet pkt;
    make_icmp_echo(&pkt, g_hosts[i].addr, ping_id);
    send_icmp_to(send_sock, &pkt, g_hosts[i].addr);
    if (++count % BATCH_SIZE == 0)
      usleep(SEND_BATCH_US);
  }

  done = 1;
  pthread_join(tid, NULL);
  close(send_sock);
  close(recv_sock);

  return count_alive();
}

/* ══════════════════════════════════════════════════════════════════════
 * Phase 2 — SYN scan receiver thread
 * ══════════════════════════════════════════════════════════════════════ */
static void *syn_receiver(void *arg) {
  struct recv_args *a = (struct recv_args *)arg;
  char buf[RECV_BUF_SIZE];

  int rst_sock = open_raw_tcp_socket();
  time_t deadline = 0;

  while (1) {
    if (*a->done && deadline == 0)
      deadline = time(NULL) + a->drain_secs;
    if (deadline && time(NULL) >= deadline)
      break;

    struct timeval tv = {.tv_sec = 0, .tv_usec = 200000};
    setsockopt(a->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t n = recv(a->sock, buf, sizeof(buf), 0);
    if (n < 0)
      continue;
    if ((size_t)n < sizeof(struct iphdr) + sizeof(struct tcphdr))
      continue;

    const struct iphdr *ip = (const struct iphdr *)buf;
    size_t ihl = (size_t)ip->ihl * 4;
    if (ihl < sizeof(struct iphdr) || (size_t)n < ihl + sizeof(struct tcphdr))
      continue;
    if (ip->protocol != IPPROTO_TCP)
      continue;
    if (ip->daddr != a->src_addr)
      continue;

    const struct tcphdr *tcp = (const struct tcphdr *)(buf + ihl);
    if (ntohs(tcp->dest) != a->sport)
      continue;

    host_entry_t *h = find_host(ip->saddr);
    if (!h)
      continue;

    uint16_t rport = ntohs(tcp->source);

    if (tcp->rst) {
      pthread_mutex_lock(&g_mu);
      if (h->state[rport] == ST_UNKNOWN)
        h->state[rport] = ST_CLOSED;
      pthread_mutex_unlock(&g_mu);
      continue;
    }

    if (tcp->syn && tcp->ack) {
      uint32_t their_seq = ntohl(tcp->seq);
      uint32_t their_ack = ntohl(tcp->ack_seq);
      uint16_t their_window = ntohs(tcp->window);

      pthread_mutex_lock(&g_mu);
      if (h->state[rport] != ST_OPEN) {
        h->state[rport] = ST_OPEN;
        h->detail[rport].seq = their_seq;
        h->detail[rport].ack_seq = their_ack;
        h->detail[rport].window = their_window;
      }
      pthread_mutex_unlock(&g_mu);

      if (rst_sock >= 0) {
        struct tcp_packet rst;
        make_rst(&rst, a->src_addr, ip->saddr, a->sport, rport, their_ack);
        send_raw_to(rst_sock, &rst, sizeof(rst), ip->saddr);
      }

      char src_str[INET_ADDRSTRLEN];
      struct in_addr sa;
      sa.s_addr = ip->saddr;
      inet_ntop(AF_INET, &sa, src_str, sizeof(src_str));
      printf("[+] OPEN  %s:%d\n", src_str, rport);
    }
  }

  if (rst_sock >= 0)
    close(rst_sock);
  return NULL;
}

/* ── Usage ────────────────────────────────────────────────────────────── */
static void usage(const char *prog) {
  (void)fprintf(stderr,
                "Usage:\n"
                "  %s <dst_ip|cidr> [output.csv] [--src <ip>] [--port <N>]\n"
                "     [--timeout <secs>] [--ping-timeout <secs>]\n\n"
                "  --src <ip>           override auto-detected source IP\n"
                "  --port <N>           scan a single port instead of 1-65535\n"
                "  --timeout <secs>     SYN drain window (default %d)\n"
                "  --ping-timeout <sec> ICMP sweep wait (default %d)\n\n"
                "  Examples:\n"
                "    %s 10.0.0.1\n"
                "    %s 10.0.0.0/24\n"
                "    %s 192.168.1.0/24 out.csv --port 80 --timeout 3\n\n"
                "  Subnet limits: /16 to /32  (up to 65534 hosts)\n"
                "  CSV columns  : host, port, output\n"
                "  output field : open  seq=<N>  ack_seq=<N>  win=<N>\n"
                "  Requires root / CAP_NET_RAW.\n",
                prog, DRAIN_SECS, PING_TIMEOUT_SECS, prog, prog, prog);
}

/* ══════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
  if (argc < 2) {
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  const char *target = argv[1];
  const char *csv_path = NULL;
  const char *src_override = NULL;
  int one_port = 0;
  int drain_secs = DRAIN_SECS;
  int ping_timeout = PING_TIMEOUT_SECS;

  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--src") == 0 && i + 1 < argc) {
      src_override = argv[++i];
    } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      int ok;
      long v = xstrtol(argv[++i], &ok);
      if (!ok || v < 1 || v > 65535) {
        (void)fprintf(stderr, "[-] Invalid port: %s\n", argv[i]);
        return EXIT_FAILURE;
      }
      one_port = (int)v;
    } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
      int ok;
      long v = xstrtol(argv[++i], &ok);
      if (!ok || v < 1) {
        (void)fprintf(stderr, "[-] Timeout must be >= 1 second\n");
        return EXIT_FAILURE;
      }
      drain_secs = (int)v;
    } else if (strcmp(argv[i], "--ping-timeout") == 0 && i + 1 < argc) {
      int ok;
      long v = xstrtol(argv[++i], &ok);
      if (!ok || v < 1) {
        (void)fprintf(stderr, "[-] Ping timeout must be >= 1 second\n");
        return EXIT_FAILURE;
      }
      ping_timeout = (int)v;
    } else {
      csv_path = argv[i];
    }
  }

  /* ── Parse target ───────────────────────────────────────────────────── */
  uint32_t base_host;
  int host_count;
  char errbuf[256];

  if (parse_cidr(target, &base_host, &host_count, errbuf, sizeof(errbuf)) < 0) {
    (void)fprintf(stderr, "[-] Bad target '%s': %s\n", target, errbuf);
    return EXIT_FAILURE;
  }

  /* ── Allocate host table ────────────────────────────────────────────── */
  g_hosts = (host_entry_t *)calloc((size_t)host_count, sizeof(host_entry_t));
  if (!g_hosts) {
    (void)fprintf(stderr, "[-] Out of memory\n");
    return EXIT_FAILURE;
  }
  g_host_count = host_count;
  for (int i = 0; i < host_count; i++)
    g_hosts[i].addr = htonl(base_host + (uint32_t)i);

  /* ── Auto-detect source IP ──────────────────────────────────────────── */
  char src_buf[INET_ADDRSTRLEN] = {0};
  const char *src_ip;

  if (src_override) {
    src_ip = src_override;
  } else {
    char first_str[INET_ADDRSTRLEN];
    struct in_addr fa;
    fa.s_addr = g_hosts[0].addr;
    inet_ntop(AF_INET, &fa, first_str, sizeof(first_str));

    if (get_local_ip(first_str, src_buf, sizeof(src_buf)) < 0) {
      (void)fprintf(stderr,
                    "[-] Could not auto-detect source IP. Use --src <ip>\n");
      free(g_hosts);
      return EXIT_FAILURE;
    }
    src_ip = src_buf;
    printf("[*] Auto-detected source IP: %s\n", src_ip);
  }

  uint32_t src_addr = inet_addr(src_ip);
  if (src_addr == INADDR_NONE) {
    (void)fprintf(stderr, "[-] Bad src IP: %s\n", src_ip);
    free(g_hosts);
    return EXIT_FAILURE;
  }

  /*
   * If our source IP is within the target subnet, mark it alive now.
   * Raw ICMP echo requests sent to ourselves never return via the wire
   * (the kernel handles them internally), so the ping sweep would miss
   * us.  Marking alive here lets phase 2 SYN-scan our own ports, which
   * works correctly on both Linux and macOS loopback.
   */
  for (int i = 0; i < host_count; i++) {
    if (g_hosts[i].addr == src_addr) {
      g_hosts[i].alive = 1;
      printf("[!] Self (%s) in subnet — skipping ping, scanning directly\n",
             src_ip);
    }
  }

  /* ── Open CSV ───────────────────────────────────────────────────────── */
  if (csv_path) {
    int is_new = (access(csv_path, F_OK) != 0);
    g_csv = fopen(csv_path, "a");
    if (!g_csv) {
      (void)fprintf(stderr, "[-] Cannot open %s: %s\n", csv_path,
                    strerror(errno));
      free(g_hosts);
      return EXIT_FAILURE;
    }
    if (is_new)
      (void)fprintf(g_csv, "host,port,output\n");
  }

  /* ══════════════════════════════════════════════════════════════════════
   * Phase 1 — ping sweep
   * ════════════════════════════════════════════════════════════════════ */
  printf("[*] Phase 1: ICMP ping sweep — %d host(s), timeout %ds...\n",
         host_count, ping_timeout);

  int alive = ping_sweep(src_addr, ping_timeout);
  if (alive < 0) {
    (void)fprintf(stderr, "[-] Ping sweep failed (socket error)\n");
    if (g_csv)
      (void)fclose(g_csv);
    free(g_hosts);
    return EXIT_FAILURE;
  }

  printf("[*] Phase 1 done: %d/%d host(s) up.\n", alive, host_count);

  if (alive == 0) {
    printf("[*] No live hosts found. Exiting.\n");
    if (g_csv)
      (void)fclose(g_csv);
    free(g_hosts);
    return EXIT_SUCCESS;
  }

  /* ══════════════════════════════════════════════════════════════════════
   * Phase 2 — SYN scan (live hosts only)
   * ════════════════════════════════════════════════════════════════════ */
  int port_lo = one_port ? one_port : 1;
  int port_hi = one_port ? one_port : PORT_MAX;

  printf(
      "[*] Phase 2: SYN scan — %d live host(s), ports %d-%d, timeout %ds...\n",
      alive, port_lo, port_hi, drain_secs);

  int send_sock = open_raw_tcp_socket();
  int recv_sock = open_raw_tcp_socket();
  if (send_sock < 0 || recv_sock < 0) {
    if (g_csv)
      (void)fclose(g_csv);
    free(g_hosts);
    return EXIT_FAILURE;
  }

  volatile int recv_done = 0;
  struct recv_args ra = {
      .sock = recv_sock,
      .src_addr = src_addr,
      .sport = SRC_PORT_FIXED,
      .done = &recv_done,
      .drain_secs = drain_secs,
  };

  pthread_t recv_tid;
  pthread_create(&recv_tid, NULL, syn_receiver, &ra);

  int syn_count = 0;
  for (int i = 0; i < host_count; i++) {
    if (!g_hosts[i].alive)
      continue; /* skip hosts that did not respond to ping */
    for (int p = port_lo; p <= port_hi; p++) {
      struct tcp_packet syn;
      make_syn(&syn, src_addr, g_hosts[i].addr, SRC_PORT_FIXED, (uint16_t)p);
      send_raw_to(send_sock, &syn, sizeof(syn), g_hosts[i].addr);
      if (++syn_count % BATCH_SIZE == 0)
        usleep(SEND_BATCH_US);
    }
  }

  printf("[*] %d SYN(s) sent. Waiting %ds for responses...\n", syn_count,
         drain_secs);
  recv_done = 1;
  pthread_join(recv_tid, NULL);
  close(send_sock);
  close(recv_sock);

  /* Mark unknowns as filtered (live hosts only) */
  for (int i = 0; i < host_count; i++) {
    if (!g_hosts[i].alive)
      continue;
    for (int p = port_lo; p <= port_hi; p++)
      if (g_hosts[i].state[p] == ST_UNKNOWN)
        g_hosts[i].state[p] = ST_FILTERED;
  }

  /* ── Summary + CSV ──────────────────────────────────────────────────── */
  int total_open = 0;

  /* Table header */
  printf("\n%-18s  %-8s  %s\n", "IP", "PORT", "STATE");
  printf("%-18s  %-8s  %s\n", "------------------", "--------", "-----");

  for (int i = 0; i < host_count; i++) {
    if (!g_hosts[i].alive)
      continue;

    char host_str[INET_ADDRSTRLEN];
    struct in_addr ha;
    ha.s_addr = g_hosts[i].addr;
    inet_ntop(AF_INET, &ha, host_str, sizeof(host_str));

    int host_open = 0;
    for (int p = port_lo; p <= port_hi; p++)
      if (g_hosts[i].state[p] == ST_OPEN)
        host_open++;

    if (host_open == 0)
      continue;

    /* Print one table row per open port; IP only on the first row */
    int first_row = 1;
    for (int p = port_lo; p <= port_hi; p++) {
      if (g_hosts[i].state[p] != ST_OPEN)
        continue;

      printf("%-18s  %-8d  open\n", first_row ? host_str : "", p);
      first_row = 0;
      total_open++;

      char out[128];
      (void)snprintf(out, sizeof(out), "open  seq=%u  ack_seq=%u  win=%u",
                     g_hosts[i].detail[p].seq, g_hosts[i].detail[p].ack_seq,
                     g_hosts[i].detail[p].window);
      csv_row(host_str, p, out);
    }

    /* Blank separator between hosts */
    printf("\n");

    /* Per-host nmap suggestion */
    printf("nmap -p ");
    int first = 1;
    for (int p = port_lo; p <= port_hi; p++) {
      if (g_hosts[i].state[p] == ST_OPEN) {
        if (!first)
          printf(",");
        printf("%d", p);
        first = 0;
      }
    }
    printf(" -sCV %s\n\n", host_str);
  }

  if (total_open == 0)
    printf("(no open ports found)\n");

  printf("[*] Done. %d open port(s) across %d live host(s).\n", total_open,
         alive);

  if (g_csv)
    (void)fclose(g_csv);
  free(g_hosts);
  return EXIT_SUCCESS;
}
