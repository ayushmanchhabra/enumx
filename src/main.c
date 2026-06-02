#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    if (check_ip_or_subnet(argv[1]) == 1) {
      if (check_public_or_private(argv[1]) == 1) {
        (void)fprintf(stdout, "Private IP detected: %s\n", argv[1]);
      } else if (check_public_or_private(argv[1]) == 0) {
        (void)fprintf(stdout, "Public IP detected: %s\n", argv[1]);
      } else {
        (void)fprintf(stderr, "Invalid IP address: %s\n", argv[1]);
        return EXIT_FAILURE;
      }
    } else if (check_ip_or_subnet(argv[1]) == 2) {
      if (check_subnet_public_or_private(argv[1]) == 1) {
        (void)fprintf(stdout, "Private subnet detected: %s\n", argv[1]);
      } else if (check_subnet_public_or_private(argv[1]) == 0) {
        (void)fprintf(stdout, "Public subnet detected: %s\n", argv[1]);
      } else {
        (void)fprintf(stderr, "Invalid subnet: %s\n", argv[1]);
        return EXIT_FAILURE;
      }
    } else {
      (void)fprintf(stderr, "Invalid IP or subnet: %s\n", argv[1]);
      return EXIT_FAILURE;
    }

    get_current_datetime(time_buffer, sizeof(time_buffer));
    (void)fprintf(stdout, "Scan complete: %s\n", time_buffer);
    if (strcmp(argv[2], "-") != 0) {
      (void)fprintf(stdout, "Scan results saved in: %s\n", argv[2]);
    }
    return EXIT_SUCCESS;
  }
}
