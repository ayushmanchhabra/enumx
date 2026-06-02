#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* If 0 then invalid, if 1 then valid IP, if 2 then valid subnet */
int check_ip_or_subnet(const char *str) {
  char buf[64];
  strncpy(buf, str, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';

  char *slash = strchr(buf, '/');
  int is_subnet = (slash != NULL);
  if (slash)
    *slash = '\0';

  char *token;
  char *rest = buf;
  int octets = 0;
  while ((token = strtok(rest, ".")) != NULL) {
    rest = NULL;
    if (++octets > 4)
      return 0;
    char *end;
    long val = strtol(token, &end, 10);
    if (*end != '\0' || val < 0 || val > 255)
      return 0;
  }
  if (octets != 4)
    return 0;

  if (is_subnet) {
    char *end;
    long prefix = strtol(slash + 1, &end, 10);
    if (*end != '\0' || prefix < 0 || prefix > 32)
      return 0;
    return 2;
  }

  return 1;
}

// Returns a heap-allocated array of IP strings, sets count.
// Caller must free: for (int i = 0; i < count; i++) free(ips[i]); free(ips);
char **expand_subnet(const char *cidr, int *count) {
  char ip_str[18];
  int prefix;
  sscanf(cidr, "%[^/]/%d", ip_str, &prefix);

  uint32_t ip;
  inet_pton(AF_INET, ip_str, &ip);
  ip = ntohl(ip);

  uint32_t netmask = prefix ? (~0u << (32 - prefix)) : 0;
  uint32_t network = ip & netmask;
  uint32_t broadcast = network | ~netmask;

  *count = broadcast - network - 1; // exclude network + broadcast
  if (*count <= 0) {
    *count = 0;
    return NULL;
  }

  char **ips = malloc(*count * sizeof(char *));
  for (int i = 0; i < *count; i++) {
    uint32_t be = htonl(network + 1 + i);
    ips[i] = malloc(16);
    inet_ntop(AF_INET, &be, ips[i], 16);
  }

  return ips;
}

void get_current_datetime(char *buffer, size_t length) {
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  (void)strftime(buffer, length, "%Y-%m-%d %H:%M:%S", t);
}
