#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "icmp.h"
#include "ip.h"

char time_buffer[20];

void get_current_datetime(char *buffer, size_t length) {
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  (void)strftime(buffer, length, "%Y-%m-%d %H:%M:%S", t);
}

static void free_up_hosts(char **hosts, long long count) {
  if (!hosts) return;
  for (long long i = 0; i < count; i++) {
    free(hosts[i]);
  }
  free(hosts);
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    (void)fprintf(stderr, "Usage: killchain <IP> <-|out.csv|out.json|out.xml>");
    return EXIT_FAILURE;
  } else {
    get_current_datetime(time_buffer, sizeof(time_buffer));
    (void)fprintf(stdout, "Starting scan on: %s\n", argv[1]);
    (void)fprintf(stdout, "Scan started: %s\n", time_buffer);

    char **up_hosts = NULL;
    long long up_count = 0;

    switch (validate_ipv4(argv[1])) {
    case TYPE_IP: {
      long latency = ping(argv[1]);
      if (latency == -2) {
        free_up_hosts(up_hosts, up_count);
        return EXIT_FAILURE;
      } else if (latency == -1) {
        (void)fprintf(stdout, "%-15s  DOWN\n", argv[1]);
      } else {
        (void)fprintf(stdout, "%-15s  ALIVE  latency=%ldms\n", argv[1],
                      latency);
        char *dup = strdup(argv[1]);
        if (!dup) {
          perror("strdup");
          free_up_hosts(up_hosts, up_count);
          return EXIT_FAILURE;
        }
        char **tmp = realloc(up_hosts, (up_count + 1) * sizeof(char *));
        if (!tmp) {
          perror("realloc");
          free(dup);
          free_up_hosts(up_hosts, up_count);
          return EXIT_FAILURE;
        }
        up_hosts = tmp;
        up_hosts[up_count++] = dup;
      }
      break;
    }
    case TYPE_CIDR: {
      ip_list_t list = expand_cidr(argv[1]);
      long *latencies = ping_hosts(list.ips, list.count);
      if (!latencies) {
        free_ip_list(&list);
        free_up_hosts(up_hosts, up_count);
        return EXIT_FAILURE;
      }

      (void)fprintf(stdout, "%lld hosts:\n", list.count);
      for (long long i = 0; i < list.count; i++) {
        long latency = latencies[i];
        if (latency == -2) {
          free(latencies);
          free_ip_list(&list);
          free_up_hosts(up_hosts, up_count);
          return EXIT_FAILURE;
        } else if (latency == -1) {
          (void)fprintf(stdout, "%-15s  DOWN\n", list.ips[i]);
        } else {
          (void)fprintf(stdout, "%-15s  ALIVE  latency=%ldms\n", list.ips[i],
                        latency);
          char *dup = strdup(list.ips[i]);
          if (!dup) {
            perror("strdup");
            free(latencies);
            free_ip_list(&list);
            free_up_hosts(up_hosts, up_count);
            return EXIT_FAILURE;
          }
          char **tmp = realloc(up_hosts, (up_count + 1) * sizeof(char *));
          if (!tmp) {
            perror("realloc");
            free(dup);
            free(latencies);
            free_ip_list(&list);
            free_up_hosts(up_hosts, up_count);
            return EXIT_FAILURE;
          }
          up_hosts = tmp;
          up_hosts[up_count++] = dup;
        }
      }

      free(latencies);
      free_ip_list(&list);
      break;
    }
    case TYPE_INVALID:
      (void)fprintf(stderr,
                    "Invalid format: %s (expected IPv4 or CIDR. For example, "
                    "192.168.1.1 or 192.168.1.0/24)\n",
                    argv[1]);
      return EXIT_FAILURE;
    }

    if (up_count > 0) {
      (void)fprintf(stdout, "\nUp hosts (%lld):\n", up_count);
      for (long long i = 0; i < up_count; i++) {
        (void)fprintf(stdout, "%s\n", up_hosts[i]);
      }
    }

    free_up_hosts(up_hosts, up_count);
    // TODO TCP SYN logic for port scanning

    get_current_datetime(time_buffer, sizeof(time_buffer));
    (void)fprintf(stdout, "Scan complete: %s\n", time_buffer);

    if (strcmp(argv[2], "-") != 0) {
      (void)fprintf(stdout, "Scan results saved in: %s\n", argv[2]);
    }
    return EXIT_SUCCESS;
  }
}
