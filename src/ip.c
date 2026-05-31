#include <arpa/inet.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IP_PATTERN "^([0-9]{1,3}\\.){3}[0-9]{1,3}$"
#define CIDR_PATTERN "^([0-9]{1,3}\\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$"

typedef enum { TYPE_IP, TYPE_CIDR, TYPE_INVALID } entry_type_t;

typedef struct {
  char **ips;
  long long count;
} ip_list_t;

entry_type_t validate_ipv4(const char *ip) {
  regex_t re_ip, re_cidr;
  entry_type_t result = TYPE_INVALID;

  regcomp(&re_ip, IP_PATTERN, REG_EXTENDED);
  regcomp(&re_cidr, CIDR_PATTERN, REG_EXTENDED);

  if (regexec(&re_ip, ip, 0, NULL, 0) == 0) {
    result = TYPE_IP;
  } else if (regexec(&re_cidr, ip, 0, NULL, 0) == 0) {
    result = TYPE_CIDR;
  }

  if (result == TYPE_IP) {
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
      result = TYPE_INVALID;
    }
  } else if (result == TYPE_CIDR) {
    char ip_part[32];
    char *slash = strchr(ip, '/');
    if (!slash) {
      result = TYPE_INVALID;
    } else {
      size_t ip_len = (size_t)(slash - ip);
      if (ip_len >= sizeof(ip_part)) {
        result = TYPE_INVALID;
      } else {
        memcpy(ip_part, ip, ip_len);
        ip_part[ip_len] = '\0';
        struct sockaddr_in sa;
        if (inet_pton(AF_INET, ip_part, &sa.sin_addr) != 1) {
          result = TYPE_INVALID;
        }
      }
    }
  }

  regfree(&re_ip);
  regfree(&re_cidr);
  return result;
}

ip_list_t expand_cidr(const char *cidr) {
  ip_list_t result = {NULL, 0};

  // Split IP and prefix
  char ip_part[32];
  int prefix;
  char *slash = strchr(cidr, '/');
  if (!slash) {
    (void)fprintf(stderr, "[!] Invalid CIDR: %s\n", cidr);
    return result;
  }

  size_t ip_len = (size_t)(slash - cidr);
  if (ip_len >= sizeof(ip_part)) {
    (void)fprintf(stderr, "[!] Invalid CIDR: %s\n", cidr);
    return result;
  }

  memcpy(ip_part, cidr, ip_len);
  ip_part[ip_len] = '\0';

  char *endptr = NULL;
  long prefix_value = strtol(slash + 1, &endptr, 10);
  if (endptr == slash + 1 || *endptr != '\0' || prefix_value < 0 ||
      prefix_value > 32) {
    (void)fprintf(stderr, "[!] Invalid prefix length: %s\n", slash + 1);
    return result;
  }
  prefix = (int)prefix_value;

  // Convert IP to integer
  struct in_addr addr;
  if (inet_pton(AF_INET, ip_part, &addr) != 1) {
    (void)fprintf(stderr, "[!] Invalid IP: %s\n", ip_part);
    return result;
  }

  uint32_t ip_int = ntohl(addr.s_addr);
  uint32_t mask = prefix == 0 ? 0 : (~0U << (32 - prefix));
  uint32_t network = ip_int & mask;
  uint32_t broadcast = network | ~mask;

  // Usable range: network+1 to broadcast-1
  uint32_t first = (prefix == 32) ? network : network + 1;
  uint32_t last = (prefix == 32)   ? network
                  : (prefix == 31) ? broadcast
                                   : broadcast - 1;

  uint32_t range = last - first;
  long long count = (long long)range + 1;

  // Allocate array
  result.ips = (char **)malloc((size_t)count * sizeof(char *));
  if (!result.ips) {
    (void)fprintf(stderr, "[!] malloc failed\n");
    return result;
  }

  // Fill array
  for (long long i = 0; i < count; i++) {
    result.ips[i] = malloc(16); // max IPv4 length "255.255.255.255\0"
    if (!result.ips[i]) {
      (void)fprintf(stderr, "[!] malloc failed at index %lld\n", i);
      for (long long j = 0; j < i; j++) {
        free(result.ips[j]);
      }
      free((void *)result.ips);
      result.ips = NULL;
      result.count = 0;
      return result;
    }

    struct in_addr a;
    a.s_addr = htonl(first + (uint32_t)i);
    inet_ntop(AF_INET, &a, result.ips[i], 16);
  }

  result.count = count;
  return result;
}

void free_ip_list(ip_list_t *list) {
  for (long long i = 0; i < list->count; i++)
    free(list->ips[i]);
  free((void *)list->ips);
  list->ips = NULL;
  list->count = 0;
}
