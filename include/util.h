#ifndef UTIL_H
#define UTIL_H

int check_ip_or_subnet(const char *str);

int parse_ip(const char *str, int oct[4]);

int check_public_or_private(const char *str);

int ip_is_private(int o[4]);

int check_subnet_public_or_private(const char *str);

void get_current_datetime(char *buffer, size_t length);

#endif
