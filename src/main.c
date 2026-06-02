#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "icmp.h"
#include "tcp.h"
#include "util.h"

char time_buffer[20];

int main(int argc, char *argv[]) {
  if (argc < 3) {
    (void)fprintf(stderr, "Usage: killchain <IP> <-|out.csv|out.json|out.xml>");
    return EXIT_FAILURE;
  } else {
    get_current_datetime(time_buffer, sizeof(time_buffer));
    (void)fprintf(stdout, "Starting scan on: %s\n", argv[1]);
    (void)fprintf(stdout, "Scan started: %s\n", time_buffer);

    char consent;
    printf("Do you want to check if host(s) are up? (y/n): ");
    scanf(" %c", &consent);
    printf("\n");

    int type = check_ip_or_subnet(argv[1]);
    if (consent == 'y' || consent == 'Y') {
      if (type == 1) {
        (void)fprintf(stdout, "IP address detected: %s\n\n", argv[1]);
        long latency = ping(argv[1]);
        (void)fprintf(stdout, "%-16s %-8s %s\n", "HOST", "STATUS", "LATENCY");
        if (latency == -2) {
          return EXIT_FAILURE;
        } else if (latency >= 0) {
          (void)fprintf(stdout, "%-16s UP      %4ld ms\n", argv[1], latency);
        } else {
          (void)fprintf(stdout, "%-16s DOWN    %4ld ms\n", argv[1], latency);
        }

      } else if (type == 2) {
        (void)fprintf(stdout, "Subnet detected: %s\n", argv[1]);
        int count;
        char **ips = expand_subnet(argv[1], &count);
        if (!ips || count <= 0) {
          (void)fprintf(stdout, "No hosts to scan in subnet %s\n", argv[1]);
          free(ips);
        } else {
          long *latencies = ping_hosts(ips, count);
          if (!latencies) {
            (void)fprintf(stderr, "Failed to perform subnet ping scan.\n");
            for (int i = 0; i < count; i++) {
              free(ips[i]);
            }
            free(ips);
            return EXIT_FAILURE;
          }

          (void)fprintf(stdout, "\n%-16s %-8s %s\n", "HOST", "STATUS",
                        "LATENCY");
          for (int i = 0; i < count; i++) {
            if (latencies[i] > 0) {
              (void)fprintf(stdout, "%-16s UP      %4ld ms\n", ips[i],
                            latencies[i]);
            }
            free(ips[i]);
          }
          free(latencies);
          free(ips);
        }
      } else {
        (void)fprintf(stdout, "Invalid IP or subnet: %s\n", argv[1]);
      }
    }

    printf("\nDo you want to check which port(s) are open? (y/n): ");
    scanf(" %c", &consent);
    printf("\n");

    if (consent == 'y' || consent == 'Y') {
      (void)fprintf(stdout, "%-16s %-8s %s\n", "HOST", "PORT", "STATUS");
      int *ports = tcp_syn(argv[1]);
      if (!ports) {
        perror("tcp_syn");
        exit(1);
      }

      for (int i = 0; ports[i] != -1; i++)
        printf("open: %d\n", ports[i]);
      free(ports);
    }

    get_current_datetime(time_buffer, sizeof(time_buffer));
    (void)fprintf(stdout, "\nScan complete: %s\n", time_buffer);
    if (strcmp(argv[2], "-") != 0) {
      (void)fprintf(stdout, "Scan results saved in: %s\n", argv[2]);
    }
    return EXIT_SUCCESS;
  }
}
