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

// Parse "a.b.c.d" into 4 octets. Returns 0 on failure.
int parse_ip(const char *str, int oct[4]) {
  return sscanf(str, "%d.%d.%d.%d", &oct[0], &oct[1], &oct[2], &oct[3]) == 4;
}

// Returns: 0 = public, 1 = private, -1 = invalid
int check_public_or_private(const char *str) {
  int o[4];
  if (!parse_ip(str, o))
    return -1;
  for (int i = 0; i < 4; i++)
    if (o[i] < 0 || o[i] > 255)
      return -1;

  // 10.0.0.0/8
  if (o[0] == 10)
    return 1;
  // 172.16.0.0/12  (172.16–172.31)
  if (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
    return 1;
  // 192.168.0.0/16
  if (o[0] == 192 && o[1] == 168)
    return 1;
  // 127.0.0.0/8  (loopback)
  if (o[0] == 127)
    return 1;
  // 169.254.0.0/16 (link-local)
  if (o[0] == 169 && o[1] == 254)
    return 1;

  return 0;
}

int ip_is_private(int o[4]) {
  for (int i = 0; i < 4; i++)
    if (o[i] < 0 || o[i] > 255)
      return -1;
  if (o[0] == 10)
    return 1; // 10.0.0.0/8
  if (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
    return 1; // 172.16.0.0/12
  if (o[0] == 192 && o[1] == 168)
    return 1; // 192.168.0.0/16
  if (o[0] == 127)
    return 1; // loopback
  if (o[0] == 169 && o[1] == 254)
    return 1; // link-local
  return 0;
}

// Returns: 0 = public, 1 = private, -1 = invalid
int check_subnet_public_or_private(const char *str) {
  char buf[64];
  strncpy(buf, str, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';

  char *slash = strchr(buf, '/');
  if (!slash)
    return -1;
  *slash = '\0';

  char *end;
  long prefix = strtol(slash + 1, &end, 10);
  if (*end != '\0' || prefix < 0 || prefix > 32)
    return -1;

  int o[4];
  if (!parse_ip(buf, o))
    return -1;
  return ip_is_private(o);
}

void get_current_datetime(char *buffer, size_t length) {
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  (void)strftime(buffer, length, "%Y-%m-%d %H:%M:%S", t);
}
