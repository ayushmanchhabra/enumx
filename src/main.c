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

    // scan(argv[1], argv[2]);

    get_current_datetime(time_buffer, sizeof(time_buffer));
    (void)fprintf(stdout, "Scan complete: %s\n", time_buffer);
    if (strcmp(argv[2], "-") != 0) {
      (void)fprintf(stdout, "Scan results saved in: %s\n", argv[2]);
    }
    return EXIT_SUCCESS;
  }
}
