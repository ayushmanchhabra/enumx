#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>

#define FIRST_PORT 1
#define LAST_PORT 65535
#define SOURCE_PORT 60000      /* ephemeral source port for outgoing SYNs   */
#define SEND_TIMEOUT_US 100000 /* send timeout: 100 ms */
#define RECV_POLL_S 1          /* recvfrom polling interval while sending    */
#define RECV_DRAIN_S 5         /* extra wait after sending for late replies  */
#define MAX_OPEN 65535

typedef struct {
  int sock;
  uint32_t target_ip; /* network byte order */
  uint32_t src_ip;    /* network byte order, filled by sender   */
  volatile int send_done;
  int open_ports[MAX_OPEN];
  uint8_t seen_ports[LAST_PORT + 1];
  volatile int open_count;
} scan_ctx;

struct pseudo_hdr {
  uint32_t src;
  uint32_t dst;
  uint8_t zero;
  uint8_t proto;
  uint16_t tcp_len;
};

static uint16_t checksum(const uint16_t *ptr, int len) {
  uint32_t sum = 0;
  while (len > 1) {
    sum += *ptr++;
    len -= 2;
  }
  if (len)
    sum += *(const uint8_t *)ptr;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (uint16_t)~sum;
}

static int build_syn(uint8_t *buf, uint32_t src_ip, uint32_t dst_ip,
                     uint16_t src_port, uint16_t dst_port) {
  memset(buf, 0, sizeof(struct iphdr) + sizeof(struct tcphdr));

  struct iphdr *ip = (struct iphdr *)buf;
  struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(struct iphdr));

  ip->ihl = 5;
  ip->version = 4;
  ip->ttl = 64;
  ip->protocol = IPPROTO_TCP;
  ip->saddr = src_ip;
  ip->daddr = dst_ip;
  ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
  /* ip->check filled by kernel (IP_HDRINCL) */

  tcp->source = htons(src_port);
  tcp->dest = htons(dst_port);
  tcp->seq = htonl(0xdeadbeef);
  tcp->doff = 5;
  tcp->syn = 1;
  tcp->window = htons(65535);

  struct {
    struct pseudo_hdr ph;
    struct tcphdr th;
  } pseudo;
  memset(&pseudo, 0, sizeof(pseudo));
  pseudo.ph.src = src_ip;
  pseudo.ph.dst = dst_ip;
  pseudo.ph.proto = IPPROTO_TCP;
  pseudo.ph.tcp_len = htons(sizeof(struct tcphdr));
  memcpy(&pseudo.th, tcp, sizeof(struct tcphdr));
  pseudo.th.check = 0;
  tcp->check = checksum((const uint16_t *)&pseudo, (int)sizeof(pseudo));

  return (int)(sizeof(struct iphdr) + sizeof(struct tcphdr));
}

static uint32_t get_src_ip(uint32_t dst_ip) {
  uint32_t src = 0;
  int u = socket(AF_INET, SOCK_DGRAM, 0);
  if (u < 0)
    return 0;

  struct sockaddr_in tmp = {
      .sin_family = AF_INET,
      .sin_port = htons(80),
      .sin_addr.s_addr = dst_ip,
  };
  if (connect(u, (struct sockaddr *)&tmp, sizeof(tmp)) == 0) {
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    if (getsockname(u, (struct sockaddr *)&local, &len) == 0)
      src = local.sin_addr.s_addr;
  }
  close(u);
  return src;
}

static void *sender_thread(void *arg) {
  scan_ctx *ctx = arg;

  ctx->src_ip = get_src_ip(ctx->target_ip);

  struct sockaddr_in dst = {
      .sin_family = AF_INET,
      .sin_addr.s_addr = ctx->target_ip,
  };
  uint8_t pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
  /* Try to make socket non-blocking so sendto won't hang indefinitely */
  int flags = fcntl(ctx->sock, F_GETFL, 0);
  if (flags >= 0) {
    (void)fcntl(ctx->sock, F_SETFL, flags | O_NONBLOCK);
  }

  for (int port = FIRST_PORT; port <= LAST_PORT; port++) {
    dst.sin_port = htons((uint16_t)port);
    int len = build_syn(pkt, ctx->src_ip, ctx->target_ip, SOURCE_PORT,
                        (uint16_t)port);

    int retries = 0;
    while (1) {
      ssize_t r = sendto(ctx->sock, pkt, (size_t)len, 0,
                         (struct sockaddr *)&dst, sizeof(dst));
      if (r >= 0) {
        break; /* sent */
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        /* send buffer full; wait briefly and retry a few times */
        if (++retries > 5) {
          /* give up on this port and move on */
          break;
        }
        usleep(1000); /* 1ms backoff */
        continue;
      }
      /* other error: break and continue with next port */
      break;
    }

    if ((port % 10000) == 0)
      usleep(1000);
  }

  /* Ensure the send_done flag is visible to the receiver thread */
  __sync_synchronize();
  ctx->send_done = 1;
  return NULL;
}

static void *receiver_thread(void *arg) {
  scan_ctx *ctx = arg;

  uint8_t buf[65536];
  struct sockaddr_in from;
  socklen_t fromlen = sizeof(from);

  while (1) {
    ssize_t n = recvfrom(ctx->sock, buf, sizeof(buf), 0,
                         (struct sockaddr *)&from, &fromlen);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        if (ctx->send_done)
          break;
        continue;
      }
      break;
    }

    if ((size_t)n < sizeof(struct iphdr) + sizeof(struct tcphdr))
      continue;

    struct iphdr *ip = (struct iphdr *)buf;
    if (ip->protocol != IPPROTO_TCP)
      continue;
    if (ip->saddr != ctx->target_ip)
      continue;

    int ip_hlen = ip->ihl * 4;
    if ((size_t)n < (size_t)ip_hlen + sizeof(struct tcphdr))
      continue;

    struct tcphdr *tcp = (struct tcphdr *)(buf + ip_hlen);

    if (tcp->syn && tcp->ack) {
      int port = ntohs(tcp->source);
      if (port >= FIRST_PORT && port <= LAST_PORT) {
        /* deduplicate */
        if (!ctx->seen_ports[port]) {
          ctx->seen_ports[port] = 1;
          int idx = __sync_fetch_and_add(&ctx->open_count, 1);
          if (idx < MAX_OPEN)
            ctx->open_ports[idx] = port;
        }
      }
    }
  }

  return NULL;
}

static int cmp_int(const void *a, const void *b) {
  return *(const int *)a - *(const int *)b;
}

int *tcp_syn(const char *ip) {
  scan_ctx *ctx = calloc(1, sizeof(*ctx));
  if (!ctx)
    return NULL;

  /* Parse target IP */
  if (inet_pton(AF_INET, ip, &ctx->target_ip) != 1) {
    errno = EINVAL;
    free(ctx);
    return NULL;
  }

  /* Open raw socket */
  ctx->sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (ctx->sock < 0) {
    free(ctx);
    return NULL;
  }

  int one = 1;
  if (setsockopt(ctx->sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    goto err;

  /* Polling recv timeout (re-set to RECV_DRAIN_S after send completes) */
  struct timeval tv = {.tv_sec = RECV_POLL_S, .tv_usec = 0};
  setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  tv.tv_sec = 0;
  tv.tv_usec = SEND_TIMEOUT_US;
  setsockopt(ctx->sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  /* Launch threads — receiver first to avoid missing early replies */
  pthread_t tid_recv, tid_send;
  if (pthread_create(&tid_recv, NULL, receiver_thread, ctx) != 0)
    goto err;
  if (pthread_create(&tid_send, NULL, sender_thread, ctx) != 0) {
    /* FIX: recv thread is running; signal it to stop and join before cleanup */
    ctx->send_done = 1;
    pthread_join(tid_recv, NULL);
    goto err;
  }

  pthread_join(tid_send, NULL);

  /* Widen recv window to drain stragglers */
  tv.tv_sec = RECV_DRAIN_S;
  tv.tv_usec = 0;
  setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  pthread_join(tid_recv, NULL);
  close(ctx->sock);

  /* FIX: clamp count to MAX_OPEN to prevent out-of-bounds qsort/memcpy */
  int count = ctx->open_count;
  if (count > MAX_OPEN)
    count = MAX_OPEN;
  qsort(ctx->open_ports, (size_t)count, sizeof(int), cmp_int);

  int *result = malloc((size_t)(count + 1) * sizeof(int));
  if (!result) {
    free(ctx);
    return NULL;
  }

  memcpy(result, ctx->open_ports, (size_t)count * sizeof(int));
  result[count] = -1; /* sentinel */

  free(ctx);
  return result;

err:
  close(ctx->sock);
  free(ctx);
  return NULL;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Optional standalone main (compile with -DSYN_SCAN_MAIN to include)
 * ════════════════════════════════════════════════════════════════════════════
 */
#ifdef SYN_SCAN_MAIN
int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <target-ip>\n", argv[0]);
    return 1;
  }

  printf("Starting SYN scan on %s (ports %d-%d)...\n", argv[1], FIRST_PORT,
         LAST_PORT);

  int *ports = tcp_syn(argv[1]);
  if (!ports) {
    perror("tcp_syn");
    return 1;
  }

  printf("\n%-10s %-10s\n", "PORT", "STATE");
  printf("%-10s %-10s\n", "----", "-----");
  int count = 0;
  for (int i = 0; ports[i] != -1; i++, count++)
    printf("%-10d open\n", ports[i]);

  printf("\nScan complete. %d open port(s) found.\n", count);
  free(ports);
  return 0;
}
#endif
