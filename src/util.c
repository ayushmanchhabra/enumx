#include <time.h>

void get_current_datetime(char *buffer, size_t length) {
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  (void)strftime(buffer, length, "%Y-%m-%d %H:%M:%S", t);
}
