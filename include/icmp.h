#ifndef ICMP_H
#define ICMP_H

long ping(const char *ip);
long *ping_hosts(char **ips, long long count);

#endif
