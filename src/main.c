#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "icmp.h"
#include "tcp.h"
#include "util.h"

char time_buffer[20];
char time_buffer_end[20];

/* ─────────────────────────────────────────────
   Data structures for collecting scan results
   ───────────────────────────────────────────── */

typedef enum { HOST_UP, HOST_DOWN } HostStatus;

typedef struct {
  char ip[64];
  HostStatus status;
  long latency_ms; /* -1 = not checked */
} HostResult;

typedef struct {
  char ip[64];
  int port;
} PortResult;

typedef struct {
  /* host-up results */
  HostResult *hosts;
  int host_count;
  int host_cap;

  /* open-port results */
  PortResult *ports;
  int port_count;
  int port_cap;

  /* metadata */
  char target[256];
  char scan_start[20];
  char scan_end[20];
} ScanResults;

/* ─────────────────────────────────────
   Dynamic-array helpers
   ───────────────────────────────────── */

static void results_init(ScanResults *r, const char *target,
                         const char *start_time) {
  memset(r, 0, sizeof(*r));
  strncpy(r->target, target, sizeof(r->target) - 1);
  strncpy(r->scan_start, start_time, sizeof(r->scan_start) - 1);
}

static void results_free(ScanResults *r) {
  free(r->hosts);
  free(r->ports);
}

static void push_host(ScanResults *r, const char *ip, HostStatus st,
                      long latency) {
  if (r->host_count >= r->host_cap) {
    r->host_cap = r->host_cap ? r->host_cap * 2 : 8;
    HostResult *tmp =
        realloc(r->hosts, (size_t)r->host_cap * sizeof(HostResult));
    if (!tmp) {
      perror("realloc (hosts)");
      return;
    }
    r->hosts = tmp;
  }
  if (!r->hosts)
    return;
  HostResult *h = &r->hosts[r->host_count++];
  strncpy(h->ip, ip, sizeof(h->ip) - 1);
  h->status = st;
  h->latency_ms = latency;
}

static void push_port(ScanResults *r, const char *ip, int port) {
  if (r->port_count >= r->port_cap) {
    r->port_cap = r->port_cap ? r->port_cap * 2 : 16;
    PortResult *tmp =
        realloc(r->ports, (size_t)r->port_cap * sizeof(PortResult));
    if (!tmp) {
      perror("realloc (ports)");
      return;
    }
    r->ports = tmp;
  }
  if (!r->ports)
    return;
  PortResult *p = &r->ports[r->port_count++];
  strncpy(p->ip, ip, sizeof(p->ip) - 1);
  p->port = port;
}

/* ─────────────────────────────────────
   Output writers
   ───────────────────────────────────── */

/* Escape a string for CSV (wrap in quotes, double any internal quotes) */
static void csv_escape(FILE *f, const char *s) {
  (void)fputc('"', f);
  for (; *s; s++) {
    if (*s == '"')
      (void)fputc('"', f);
    (void)fputc(*s, f);
  }
  (void)fputc('"', f);
}

/* Escape a string for XML */
static void xml_escape(FILE *f, const char *s) {
  for (; *s; s++) {
    switch (*s) {
    case '&':
      (void)fputs("&amp;", f);
      break;
    case '<':
      (void)fputs("&lt;", f);
      break;
    case '>':
      (void)fputs("&gt;", f);
      break;
    case '"':
      (void)fputs("&quot;", f);
      break;
    case '\'':
      (void)fputs("&apos;", f);
      break;
    default:
      (void)fputc(*s, f);
    }
  }
}

/* Escape a string for JSON */
static void json_escape(FILE *f, const char *s) {
  (void)fputc('"', f);
  for (; *s; s++) {
    switch (*s) {
    case '"':
      (void)fputs("\\\"", f);
      break;
    case '\\':
      (void)fputs("\\\\", f);
      break;
    case '\n':
      (void)fputs("\\n", f);
      break;
    case '\r':
      (void)fputs("\\r", f);
      break;
    case '\t':
      (void)fputs("\\t", f);
      break;
    default:
      (void)fputc(*s, f);
    }
  }
  (void)fputc('"', f);
}

static void write_csv(const char *path, const ScanResults *r) {
  FILE *f = fopen(path, "w");
  if (!f) {
    perror("fopen (csv)");
    return;
  }

  /* Metadata header */
  (void)fprintf(f, "# Killchain scan report\n");
  (void)fprintf(f, "# Target,%s\n", r->target);
  (void)fprintf(f, "# Scan start,%s\n", r->scan_start);
  (void)fprintf(f, "# Scan end,%s\n\n", r->scan_end);

  /* Host-up section */
  (void)fprintf(f, "section,host,status,latency_ms\n");
  for (int i = 0; i < r->host_count; i++) {
    const HostResult *h = &r->hosts[i];
    (void)fprintf(f, "host,");
    csv_escape(f, h->ip);
    (void)fprintf(f, ",%s", h->status == HOST_UP ? "UP" : "DOWN");
    if (h->latency_ms >= 0)
      (void)fprintf(f, ",%ld\n", h->latency_ms);
    else
      (void)fprintf(f, ",N/A\n");
  }

  /* Port section */
  (void)fprintf(f, "\nsection,host,port,state\n");
  for (int i = 0; i < r->port_count; i++) {
    const PortResult *p = &r->ports[i];
    (void)fprintf(f, "port,");
    csv_escape(f, p->ip);
    (void)fprintf(f, ",%d,OPEN\n", p->port);
  }

  (void)fclose(f);
}

static void write_json(const char *path, const ScanResults *r) {
  FILE *f = fopen(path, "w");
  if (!f) {
    perror("fopen (json)");
    return;
  }

  (void)fprintf(f, "{\n");
  (void)fprintf(f, "  \"scan\": {\n");
  (void)fprintf(f, "    \"target\": ");
  json_escape(f, r->target);
  (void)fprintf(f, ",\n    \"start\": ");
  json_escape(f, r->scan_start);
  (void)fprintf(f, ",\n    \"end\": ");
  json_escape(f, r->scan_end);
  (void)fprintf(f, "\n  },\n");

  /* hosts */
  (void)fprintf(f, "  \"hosts\": [\n");
  for (int i = 0; i < r->host_count; i++) {
    const HostResult *h = &r->hosts[i];
    (void)fprintf(f, "    { \"ip\": ");
    json_escape(f, h->ip);
    (void)fprintf(f, ", \"status\": \"%s\"",
                  h->status == HOST_UP ? "UP" : "DOWN");
    if (h->latency_ms >= 0)
      (void)fprintf(f, ", \"latency_ms\": %ld", h->latency_ms);
    else
      (void)fprintf(f, ", \"latency_ms\": null");
    (void)fprintf(f, " }%s\n", i + 1 < r->host_count ? "," : "");
  }
  (void)fprintf(f, "  ],\n");

  /* ports */
  (void)fprintf(f, "  \"open_ports\": [\n");
  for (int i = 0; i < r->port_count; i++) {
    const PortResult *p = &r->ports[i];
    (void)fprintf(f, "    { \"ip\": ");
    json_escape(f, p->ip);
    (void)fprintf(f, ", \"port\": %d, \"state\": \"OPEN\" }%s\n", p->port,
                  i + 1 < r->port_count ? "," : "");
  }
  (void)fprintf(f, "  ]\n");
  (void)fprintf(f, "}\n");

  (void)fclose(f);
}

static void write_xml(const char *path, const ScanResults *r) {
  FILE *f = fopen(path, "w");
  if (!f) {
    perror("fopen (xml)");
    return;
  }

  (void)fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
  (void)fprintf(f, "<killchain>\n");
  (void)fprintf(f, "  <scan>\n");
  (void)fprintf(f, "    <target>");
  xml_escape(f, r->target);
  (void)fprintf(f, "</target>\n");
  (void)fprintf(f, "    <start>");
  xml_escape(f, r->scan_start);
  (void)fprintf(f, "</start>\n");
  (void)fprintf(f, "    <end>");
  xml_escape(f, r->scan_end);
  (void)fprintf(f, "</end>\n");
  (void)fprintf(f, "  </scan>\n");

  (void)fprintf(f, "  <hosts>\n");
  for (int i = 0; i < r->host_count; i++) {
    const HostResult *h = &r->hosts[i];
    (void)fprintf(f, "    <host>\n");
    (void)fprintf(f, "      <ip>");
    xml_escape(f, h->ip);
    (void)fprintf(f, "</ip>\n");
    (void)fprintf(f, "      <status>%s</status>\n",
                  h->status == HOST_UP ? "UP" : "DOWN");
    if (h->latency_ms >= 0)
      (void)fprintf(f, "      <latency_ms>%ld</latency_ms>\n", h->latency_ms);
    else
      (void)fprintf(f, "      <latency_ms/>\n");
    (void)fprintf(f, "    </host>\n");
  }
  (void)fprintf(f, "  </hosts>\n");

  (void)fprintf(f, "  <open_ports>\n");
  for (int i = 0; i < r->port_count; i++) {
    const PortResult *p = &r->ports[i];
    (void)fprintf(f, "    <port>\n");
    (void)fprintf(f, "      <ip>");
    xml_escape(f, p->ip);
    (void)fprintf(f, "</ip>\n");
    (void)fprintf(f, "      <number>%d</number>\n", p->port);
    (void)fprintf(f, "      <state>OPEN</state>\n");
    (void)fprintf(f, "    </port>\n");
  }
  (void)fprintf(f, "  </open_ports>\n");
  (void)fprintf(f, "</killchain>\n");

  (void)fclose(f);
}

/* Detect output format from file extension.
   Returns: 'c'=csv, 'j'=json, 'x'=xml, 0=stdout/unknown */
static char detect_format(const char *path) {
  if (strcmp(path, "-") == 0)
    return 0;
  const char *dot = strrchr(path, '.');
  if (!dot)
    return 0;
  if (strcasecmp(dot, ".csv") == 0)
    return 'c';
  if (strcasecmp(dot, ".json") == 0)
    return 'j';
  if (strcasecmp(dot, ".xml") == 0)
    return 'x';
  return 0;
}

static void save_results(const char *path, ScanResults *r) {
  char fmt = detect_format(path);
  switch (fmt) {
  case 'c':
    write_csv(path, r);
    break;
  case 'j':
    write_json(path, r);
    break;
  case 'x':
    write_xml(path, r);
    break;
  default:
    (void)fprintf(stderr,
                  "[!] Unrecognised output format for '%s'. "
                  "Use .csv / .json / .xml or '-' for stdout.\n",
                  path);
  }
}

/* ─────────────────────────────────────
   main
   ───────────────────────────────────── */

int main(int argc, char *argv[]) {
  if (argc < 3) {
    (void)fprintf(stderr,
                  "Usage: killchain <IP|CIDR> <-|out.csv|out.json|out.xml>\n");
    return EXIT_FAILURE;
  }

  char consent;
  printf("[!] By using this tool you confirm you have explicit permission to "
         "test the target.\nUnauthorized use is illegal and is your sole "
         "responsibility. Proceed? (y/n): ");
  (void)scanf(" %c", &consent);
  if (consent == 'n' || consent == 'N')
    return EXIT_FAILURE;

  get_current_datetime(time_buffer, sizeof(time_buffer));
  (void)fprintf(stdout, "Starting scan on: %s\n", argv[1]);
  (void)fprintf(stdout, "Scan started: %s\n", time_buffer);

  ScanResults results;
  results_init(&results, argv[1], time_buffer);

  int ret = EXIT_SUCCESS;
  int type = check_ip_or_subnet(argv[1]);

  /* ── Host-up check ── */
  printf("\nDo you want to check if host(s) are up? (y/n): ");
  (void)scanf(" %c", &consent);
  printf("\n");

  if (consent == 'y' || consent == 'Y') {
    if (type == 1) {
      (void)fprintf(stdout, "IP address detected: %s\n\n", argv[1]);
      long latency = ping(argv[1]);
      (void)fprintf(stdout, "%-16s %-8s %s\n", "HOST", "STATUS", "LATENCY");
      if (latency == -2) {
        ret = EXIT_FAILURE;
        goto cleanup;
      } else if (latency >= 0) {
        (void)fprintf(stdout, "%-16s UP      %4ld ms\n", argv[1], latency);
        push_host(&results, argv[1], HOST_UP, latency);
      } else {
        (void)fprintf(stdout, "%-16s DOWN    %4ld ms\n", argv[1], latency);
        push_host(&results, argv[1], HOST_DOWN, -1);
      }

    } else if (type == 2) {
      (void)fprintf(stdout, "Subnet detected: %s\n", argv[1]);
      int count;
      char **ips = expand_subnet(argv[1], &count);
      if (!ips || count <= 0) {
        (void)fprintf(stdout, "No hosts to scan in subnet %s\n", argv[1]);
        if (ips) {
          for (int i = 0; i < count; i++)
            free(ips[i]);
          free((void *)ips);
        }
      } else {
        long *latencies = ping_hosts(ips, count);
        if (!latencies) {
          (void)fprintf(stderr, "Failed to perform subnet ping scan.\n");
          for (int i = 0; i < count; i++)
            free(ips[i]);
          free((void *)ips);
          ret = EXIT_FAILURE;
          goto cleanup;
        }

        (void)fprintf(stdout, "\n%-16s %-8s %s\n", "HOST", "STATUS", "LATENCY");
        for (int i = 0; i < count; i++) {
          if (latencies[i] >= 0) {
            (void)fprintf(stdout, "%-16s UP      %4ld ms\n", ips[i],
                          latencies[i]);
            push_host(&results, ips[i], HOST_UP, latencies[i]);
          } else {
            push_host(&results, ips[i], HOST_DOWN, -1);
          }
          free(ips[i]);
        }
        free(latencies);
        free((void *)ips);
      }
    } else {
      (void)fprintf(stdout, "Invalid IP or subnet: %s\n", argv[1]);
    }
  }

  /* ── Port scan ── */
  printf("\nDo you want to check which port(s) are open? (y/n): ");
  (void)scanf(" %c", &consent);
  printf("\n");

  if (consent == 'y' || consent == 'Y') {
    int scan_type = check_ip_or_subnet(argv[1]);
    int found_total = 0;

    if (scan_type == 1) {
      int *ports = tcp_syn(argv[1]);
      if (!ports) {
        perror("tcp_syn");
        ret = EXIT_FAILURE;
        goto cleanup;
      }

      (void)printf("%-16s %-8s %s\n", "HOST", "PORT", "STATE");
      int found = 0;
      for (int i = 0; ports[i] != -1; i++) {
        (void)printf("%-16s %-8d %s\n", argv[1], ports[i], "OPEN");
        push_port(&results, argv[1], ports[i]);
        found++;
      }
      (void)printf("\n%d open port(s) found.\n", found);
      free(ports);

    } else if (scan_type == 2) {
      (void)fprintf(stdout, "Subnet detected: %s\n", argv[1]);
      int count;
      char **ips = expand_subnet(argv[1], &count);
      if (!ips || count <= 0) {
        (void)fprintf(stdout, "No hosts to scan in subnet %s\n", argv[1]);
        if (ips) {
          for (int i = 0; i < count; i++)
            free(ips[i]);
          free((void *)ips);
        }
      } else {
        (void)printf("%-16s %-8s %s\n", "HOST", "PORT", "STATE");
        for (int h = 0; h < count; h++) {
          int *ports = tcp_syn(ips[h]);
          if (!ports) {
            (void)fprintf(stderr, "tcp_syn failed for %s\n", ips[h]);
            continue;
          }
          int found = 0;
          for (int p = 0; ports[p] != -1; p++) {
            (void)printf("%-16s %-8d %s\n", ips[h], ports[p], "OPEN");
            push_port(&results, ips[h], ports[p]);
            found++;
          }
          found_total += found;
          free(ports);
        }
        for (int i = 0; i < count; i++)
          free(ips[i]);
        free((void *)ips);
        (void)printf("\n%d open port(s) found across subnet.\n", found_total);
      }
    } else {
      (void)fprintf(stdout, "Invalid IP or subnet: %s\n", argv[1]);
    }
  }

  /* ── Wrap up ── */
  get_current_datetime(time_buffer_end, sizeof(time_buffer_end));
  strncpy(results.scan_end, time_buffer_end, sizeof(results.scan_end) - 1);

  if (strcmp(argv[2], "-") != 0) {
    save_results(argv[2], &results);
  }

cleanup:
  results_free(&results);

  if (ret == EXIT_SUCCESS) {
    (void)fprintf(stdout, "\nScan complete: %s\n", time_buffer_end);
    if (strcmp(argv[2], "-") != 0) {
      (void)fprintf(stdout, "Scan results saved in: %s\n", argv[2]);
    }
  }

  return ret;
}
