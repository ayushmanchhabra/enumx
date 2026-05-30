#include <arpa/inet.h>
#include <netinet/in.h>
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

long ping(const char *ip) {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock < 0) {
    (void)fprintf(stderr, "ICMP requires root (CAP_NET_RAW). Run with sudo.\n");
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
  pkt.un.echo.id = getpid();
  pkt.un.echo.sequence = 1;
  pkt.checksum = checksum(&pkt, sizeof(pkt));

  struct timeval start, end;
  gettimeofday(&start, NULL);

  if (sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&dest,
             sizeof(dest)) <= 0) {
    perror("[!] sendto");
    close(sock);
    return -1;
  }

  char buf[1024];
  struct sockaddr_in reply;
  socklen_t reply_len = sizeof(reply);

  long latency = -1;
  if (recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&reply,
               &reply_len) > 0) {
    gettimeofday(&end, NULL);
    latency = (end.tv_sec - start.tv_sec) * 1000 +
              (end.tv_usec - start.tv_usec) / 1000;
  }

  close(sock);
  return latency;
}
