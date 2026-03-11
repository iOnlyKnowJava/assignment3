/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

#include <stdio.h>
#include <stdlib.h>

#include "ut_tcp.h"

void functionality(ut_socket_t *sock) {
  char buf[9898];
  FILE *fp;
  int n;
  int file_length = 51200;
  int read = 0;

  fp = fopen("/tmp/grader_rel_output", "w+");
  while (read < file_length) {
    n = ut_read(sock, buf, 9898, NO_FLAG);
    read += n;
    fwrite(buf, 1, n, fp);
  }
  fclose(fp);
}

int main(int argc, char **argv) {
  int portno;
  char *serverip;
  ut_socket_t socket;

  serverip = "127.0.0.1";

  if (argc > 1) {
    portno = atoi(argv[1]);
  } else {
    portno = 12000;
  }

  if (ut_socket(&socket, TCP_LISTENER, portno, serverip) < 0)
    exit(EXIT_FAILURE);

  functionality(&socket);

  ut_close(&socket);

  return EXIT_SUCCESS;
}
