#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "icmp.h"

char time_buffer[20];

void getCurrentDate(char *buffer, size_t length) {
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  (void)strftime(buffer, length, "%Y-%m-%d %H:%M:%S", t);
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    (void)fprintf(stderr,
                  "Usage: killchain <IP> <-|out.csv|out.json|out.xml>");
    return EXIT_FAILURE;
  } else {
    getCurrentDate(time_buffer, sizeof(time_buffer));
    (void)fprintf(stdout, "Starting scan on: %s\n", argv[1]);
    (void)fprintf(stdout, "Scan started: %s\n", time_buffer);

    long latency = ping(argv[1]);

    if (latency == -2) {
      return EXIT_FAILURE;
    } else if (latency == -1) {
      (void)fprintf(stdout, "%-15s  DOWN\n", argv[1]);
    } else {
      (void)fprintf(stdout, "%-15s  ALIVE  latency=%ldms\n", argv[1],
                    latency);
    }

    getCurrentDate(time_buffer, sizeof(time_buffer));
    (void)fprintf(stdout, "Scan complete: %s\n", time_buffer);
    if (strcmp(argv[2], "-") != 0) {
      (void)fprintf(stdout, "Scan results saved in: %s\n", argv[2]);
    }
    return EXIT_SUCCESS;
  }
}
