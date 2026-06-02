#ifndef UTIL_H
#define UTIL_H

int check_ip_or_subnet(const char *str);

char **expand_subnet(const char *cidr, int *count);

void get_current_datetime(char *buffer, size_t length);

#endif
