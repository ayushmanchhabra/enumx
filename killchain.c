/*
 * killchain.c — TCP half-open (SYN) scanner
 *
 * Scans all ports 1-65535 on a target by default, or a single port if
 * supplied.  Uses one raw socket per direction:
 *   - sender thread  : fires SYNs as fast as the semaphore allows
 *   - receiver thread: collects SYN-ACKs / RSTs until the drain window closes
 *
 * Every open port is appended as one CSV row:
 *   host, port, output
 * where "output" contains detailed SYN-ACK info (seq, ack_seq, window).
 *
 * Usage:
 *   sudo ./killchain <dst_ip> [output.csv] [--src <ip>] [--port <N>] [--timeout
 * <secs>]
 *
 * Requires root / CAP_NET_RAW.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
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
#define SRC_PORT_FIXED 60000 /* fixed sport so receiver can filter    */
#define RECV_BUF_SIZE 65536
#define DRAIN_SECS 5      /* default drain window (overridable)    */
#define SEND_BATCH_US 500 /* µs sleep every BATCH_SIZE sends       */
#define BATCH_SIZE 128    /* sends before each sleep               */

/* ── Port state table ─────────────────────────────────────────────────── */
#define PORT_MAX 65535

typedef enum { ST_UNKNOWN = 0, ST_OPEN, ST_CLOSED, ST_FILTERED } port_state_t;

static port_state_t g_state[PORT_MAX + 1];
static pthread_mutex_t g_state_mu = PTHREAD_MUTEX_INITIALIZER;

/* Per-port SYN-ACK detail captured for CSV output */
typedef struct {
  uint32_t seq;     /* their ISN (seq in SYN-ACK)   */
  uint32_t ack_seq; /* their ack of our SYN          */
  uint16_t window;  /* advertised receive window     */
} port_detail_t;

static port_detail_t g_detail[PORT_MAX + 1];

/* ── CSV helpers ──────────────────────────────────────────────────────── */
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
    } else if (*s == '\r') { /* skip */
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

/* ── Types ────────────────────────────────────────────────────────────── */
struct pseudo_header {
  uint32_t src, dst;
  uint8_t zero, proto;
  uint16_t tcp_len;
};

struct packet {
  struct iphdr ip;
  struct tcphdr tcp;
};

struct recv_args {
  int sock;
  uint32_t src_addr;
  uint32_t dst_addr;
  uint16_t sport;
  volatile int *done;
  const char *dst_ip;
  int drain_secs;
};

/* ── strtol helpers ───────────────────────────────────────────────────── */
/* Returns 0 and sets *ok=0 on any parse error; sets *ok=1 on success.    */
static long xstrtol(const char *s, int *ok) {
  char *end;
  errno = 0;
  long v = strtol(s, &end, 10);
  *ok = (errno == 0 && end != s && *end == '\0');
  return v;
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

/* ── Packet builders ──────────────────────────────────────────────────── */
static void fill_ip(struct iphdr *ip, uint32_t src, uint32_t dst) {
  ip->version = 4;
  ip->ihl = sizeof(struct iphdr) / 4;
  ip->tot_len = htons(sizeof(struct packet));
  ip->id = htons((uint16_t)(arc4random() & 0xffff));
  ip->frag_off = htons(IP_DF);
  ip->ttl = DEFAULT_TTL;
  ip->protocol = IPPROTO_TCP;
  ip->saddr = src;
  ip->daddr = dst;
}

static void tcp_checksum(struct packet *pkt) {
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

static void make_syn(struct packet *pkt, uint32_t src, uint32_t dst,
                     uint16_t sport, uint16_t dport) {
  memset(pkt, 0, sizeof(*pkt));
  fill_ip(&pkt->ip, src, dst);
  pkt->tcp.source = htons(sport);
  pkt->tcp.dest = htons(dport);
  pkt->tcp.seq = htonl(arc4random());
  pkt->tcp.doff = sizeof(struct tcphdr) / 4;
  pkt->tcp.syn = 1;
  pkt->tcp.window = htons(DEFAULT_WINDOW);
  tcp_checksum(pkt);
}

static void make_rst(struct packet *pkt, uint32_t src, uint32_t dst,
                     uint16_t sport, uint16_t dport, uint32_t seq) {
  memset(pkt, 0, sizeof(*pkt));
  fill_ip(&pkt->ip, src, dst);
  pkt->tcp.source = htons(sport);
  pkt->tcp.dest = htons(dport);
  pkt->tcp.seq = htonl(seq);
  pkt->tcp.doff = sizeof(struct tcphdr) / 4;
  pkt->tcp.rst = 1;
  tcp_checksum(pkt);
}

/* ── Raw socket helpers ───────────────────────────────────────────────── */
static int open_raw_socket(void) {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sock < 0) {
    perror("socket (needs root/CAP_NET_RAW)");
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

static int send_raw(int sock, struct packet *pkt) {
  struct sockaddr_in dst = {
      .sin_family = AF_INET,
      .sin_port = pkt->tcp.dest,
      .sin_addr.s_addr = pkt->ip.daddr,
  };
  return (int)sendto(sock, pkt, sizeof(*pkt), 0, (struct sockaddr *)&dst,
                     sizeof(dst));
}

/* ── Receiver thread ──────────────────────────────────────────────────── */
static void *receiver(void *arg) {
  struct recv_args *a = (struct recv_args *)arg;
  char buf[RECV_BUF_SIZE];

  int rst_sock = open_raw_socket();
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

    if (ip->saddr != a->dst_addr)
      continue;
    if (ip->daddr != a->src_addr)
      continue;

    const struct tcphdr *tcp = (const struct tcphdr *)(buf + ihl);
    if (ntohs(tcp->dest) != a->sport)
      continue;

    uint16_t rport = ntohs(tcp->source);

    if (tcp->rst) {
      pthread_mutex_lock(&g_state_mu);
      if (g_state[rport] == ST_UNKNOWN)
        g_state[rport] = ST_CLOSED;
      pthread_mutex_unlock(&g_state_mu);
      continue;
    }

    if (tcp->syn && tcp->ack) {
      uint32_t their_seq = ntohl(tcp->seq);
      uint32_t their_ack = ntohl(tcp->ack_seq);
      uint16_t their_window = ntohs(tcp->window);

      pthread_mutex_lock(&g_state_mu);
      if (g_state[rport] != ST_OPEN) {
        g_state[rport] = ST_OPEN;
        g_detail[rport].seq = their_seq;
        g_detail[rport].ack_seq = their_ack;
        g_detail[rport].window = their_window;
      }
      pthread_mutex_unlock(&g_state_mu);

      if (rst_sock >= 0) {
        struct packet rst;
        make_rst(&rst, a->src_addr, a->dst_addr, a->sport, rport, their_ack);
        send_raw(rst_sock, &rst);
      }

      printf("[+] OPEN  %s:%d\n", a->dst_ip, rport);
    }
  }

  if (rst_sock >= 0)
    close(rst_sock);
  return NULL;
}

/* ── Usage ────────────────────────────────────────────────────────────── */
static void usage(const char *prog) {
  (void)fprintf(
      stderr,
      "Usage:\n"
      "  %s <dst_ip> [output.csv] [--src <ip>] [--port <N>] [--timeout "
      "<secs>]\n\n"
      "  --src <ip>       override auto-detected source IP\n"
      "  --port <N>       scan a single port instead of 1-65535\n"
      "  --timeout <secs> drain window after last SYN (default %d)\n\n"
      "  CSV columns : host, port, output\n"
      "  output field: open  seq=<N>  ack_seq=<N>  win=<N>\n"
      "  Requires root / CAP_NET_RAW.\n",
      prog, DRAIN_SECS);
}

/* ══════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
  if (argc < 2) {
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  const char *dst_ip = argv[1];
  const char *csv_path = NULL;
  const char *src_override = NULL;
  int one_port = 0;
  int drain_secs = DRAIN_SECS;

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
    } else {
      csv_path = argv[i];
    }
  }

  uint32_t dst_addr = inet_addr(dst_ip);
  if (dst_addr == INADDR_NONE) {
    (void)fprintf(stderr, "[-] Bad dst IP: %s\n", dst_ip);
    return EXIT_FAILURE;
  }

  char src_buf[INET_ADDRSTRLEN] = {0};
  const char *src_ip;

  if (src_override) {
    src_ip = src_override;
  } else {
    if (get_local_ip(dst_ip, src_buf, sizeof(src_buf)) < 0) {
      (void)fprintf(stderr,
                    "[-] Could not auto-detect source IP. Use --src <ip>\n");
      return EXIT_FAILURE;
    }
    src_ip = src_buf;
    printf("[*] Auto-detected source IP: %s\n", src_ip);
  }

  uint32_t src_addr = inet_addr(src_ip);
  if (src_addr == INADDR_NONE) {
    (void)fprintf(stderr, "[-] Bad src IP: %s\n", src_ip);
    return EXIT_FAILURE;
  }

  if (csv_path) {
    int is_new = (access(csv_path, F_OK) != 0);
    g_csv = fopen(csv_path, "a");
    if (!g_csv) {
      (void)fprintf(stderr, "[-] Cannot open %s: %s\n", csv_path,
                    strerror(errno));
      return EXIT_FAILURE;
    }
    if (is_new)
      (void)fprintf(g_csv, "host,port,output\n");
  }

  int send_sock = open_raw_socket();
  int recv_sock = open_raw_socket();
  if (send_sock < 0 || recv_sock < 0)
    return EXIT_FAILURE;

  volatile int recv_done = 0;

  struct recv_args ra = {
      .sock = recv_sock,
      .src_addr = src_addr,
      .dst_addr = dst_addr,
      .sport = SRC_PORT_FIXED,
      .done = &recv_done,
      .dst_ip = dst_ip,
      .drain_secs = drain_secs,
  };

  pthread_t recv_tid;
  pthread_create(&recv_tid, NULL, receiver, &ra);

  int port_lo = one_port ? one_port : 1;
  int port_hi = one_port ? one_port : PORT_MAX;

  printf("[*] Scanning %s ports %d-%d (src %s sport %d timeout %ds)...\n",
         dst_ip, port_lo, port_hi, src_ip, SRC_PORT_FIXED, drain_secs);

  int count = 0;
  for (int p = port_lo; p <= port_hi; p++) {
    struct packet syn;
    make_syn(&syn, src_addr, dst_addr, SRC_PORT_FIXED, (uint16_t)p);
    send_raw(send_sock, &syn);
    if (++count % BATCH_SIZE == 0)
      usleep(SEND_BATCH_US);
  }

  printf("[*] SYNs sent. Waiting %ds for responses...\n", drain_secs);
  recv_done = 1;
  pthread_join(recv_tid, NULL);

  close(send_sock);
  close(recv_sock);

  for (int p = port_lo; p <= port_hi; p++)
    if (g_state[p] == ST_UNKNOWN)
      g_state[p] = ST_FILTERED;

  int open_count = 0;
  printf("\n%-8s  %s\n", "PORT", "STATE");
  for (int p = port_lo; p <= port_hi; p++) {
    if (g_state[p] == ST_OPEN) {
      printf("%-8d  open\n", p);
      open_count++;

      char out[128];
      (void)snprintf(out, sizeof(out), "open  seq=%u  ack_seq=%u  win=%u",
                     g_detail[p].seq, g_detail[p].ack_seq, g_detail[p].window);
      csv_row(dst_ip, p, out);
    }
  }

  if (open_count == 0) {
    printf("(no open ports found)\n");
  } else {
    printf("\nnmap -p ");
    int first = 1;
    for (int p = port_lo; p <= port_hi; p++) {
      if (g_state[p] == ST_OPEN) {
        if (!first)
          printf(",");
        printf("%d", p);
        first = 0;
      }
    }
    printf(" -sCV %s\n", dst_ip);
  }

  printf("\n[*] Done. %d open port(s).\n", open_count);

  if (g_csv)
    (void)fclose(g_csv);
  return EXIT_SUCCESS;
}
