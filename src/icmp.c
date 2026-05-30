#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define TIMEOUT_SEC 2

unsigned short checksum(void *b, int len) {
  unsigned short *buf = b;
  unsigned int sum = 0;
  for (; len > 1; len -= 2)
    sum += *buf++;
  if (len == 1)
    sum += *(unsigned char *)buf;
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return ~sum;
}

static long compute_latency(const struct timeval *start, const struct timeval *end) {
  return (end->tv_sec - start->tv_sec) * 1000 +
         (end->tv_usec - start->tv_usec) / 1000;
}

long *ping_hosts(char **ips, long long count) {
  if (count <= 0) {
    return NULL;
  }

  long *latencies = malloc((size_t)count * sizeof(long));
  if (!latencies) {
    return NULL;
  }

  struct timeval *start_times = malloc((size_t)count * sizeof(struct timeval));
  if (!start_times) {
    free(latencies);
    return NULL;
  }

  for (long long i = 0; i < count; i++) {
    latencies[i] = -1;
  }

  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock < 0) {
    (void)fprintf(
        stderr,
        "ICMP requires uses CAP_NET_RAW which required root. Run with sudo.\n");
    free(latencies);
    free(start_times);
    return NULL;
  }

  struct timeval tv = {TIMEOUT_SEC, 0};
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  for (long long i = 0; i < count; i++) {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ips[i]);

    struct icmphdr pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = ICMP_ECHO;
    pkt.code = 0;
    pkt.un.echo.id = htons((uint16_t)getpid());
    pkt.un.echo.sequence = htons((uint16_t)(i + 1));
    pkt.checksum = checksum(&pkt, sizeof(pkt));

    gettimeofday(&start_times[i], NULL);
    if (sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&dest,
               sizeof(dest)) <= 0) {
      latencies[i] = -2;
    }
  }

  long long remaining = count;
  unsigned char buf[1024];
  while (remaining > 0) {
    struct sockaddr_in reply;
    socklen_t reply_len = sizeof(reply);
    ssize_t len = recvfrom(sock, buf, sizeof(buf), 0,
                           (struct sockaddr *)&reply, &reply_len);
    if (len <= 0) {
      break;
    }

    if ((size_t)len < sizeof(struct iphdr) + sizeof(struct icmphdr)) {
      continue;
    }

    struct iphdr *ip_hdr = (struct iphdr *)buf;
    size_t ip_hdr_len = (size_t)ip_hdr->ihl * 4;
    if ((size_t)len < ip_hdr_len + sizeof(struct icmphdr)) {
      continue;
    }

    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + ip_hdr_len);
    if (icmp_hdr->type != ICMP_ECHOREPLY) {
      continue;
    }

    if (icmp_hdr->un.echo.id != htons((uint16_t)getpid())) {
      continue;
    }

    uint16_t seq = ntohs(icmp_hdr->un.echo.sequence);
    if (seq == 0 || seq > (uint16_t)count) {
      continue;
    }

    long long index = (long long)seq - 1;
    if (latencies[index] != -1) {
      continue;
    }

    struct timeval recv_time;
    gettimeofday(&recv_time, NULL);
    latencies[index] = compute_latency(&start_times[index], &recv_time);
    remaining--;
  }

  close(sock);
  free(start_times);
  return latencies;
}

long ping(const char *ip) {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock < 0) {
    (void)fprintf(
        stderr,
        "ICMP requires uses CAP_NET_RAW which required root. Run with sudo.\n");
    return -2;
  }

  struct timeval tv = {TIMEOUT_SEC, 0};
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = inet_addr(ip);

  struct icmphdr pkt;
  memset(&pkt, 0, sizeof(pkt));
  pkt.type = ICMP_ECHO;
  pkt.code = 0;
  pkt.un.echo.id = htons((uint16_t)getpid());
  pkt.un.echo.sequence = htons(1);
  pkt.checksum = checksum(&pkt, sizeof(pkt));

  struct timeval start, end;
  gettimeofday(&start, NULL);

  if (sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&dest,
             sizeof(dest)) <= 0) {
    (void)fprintf(stderr, "Failed to send ICMP packet to %s\n", ip);
    close(sock);
    return -2;
  }

  unsigned char buf[1024];
  struct sockaddr_in reply;
  socklen_t reply_len = sizeof(reply);

  long latency = -1;
  if (recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&reply,
               &reply_len) > 0) {
    gettimeofday(&end, NULL);
    latency = compute_latency(&start, &end);
  }

  close(sock);
  return latency;
}
