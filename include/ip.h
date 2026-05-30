#ifndef IP_H
#define IP_H

typedef enum { TYPE_IP, TYPE_CIDR, TYPE_INVALID } entry_type_t;

entry_type_t validate_ipv4(const char *input);

typedef struct {
  char **ips;
  long long count;
} ip_list_t;

ip_list_t expand_cidr(const char *cidr);

void free_ip_list(ip_list_t *list);

#endif
