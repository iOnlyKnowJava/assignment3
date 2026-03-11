/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ut_tcp.h"

void functionality(ut_socket_t *sock) {
  char buf[9898];
  int n;
  int file_length = 204800;
  int read = 0;

  while (read < file_length) {
    n = ut_read(sock, buf, 30000, NO_FLAG);
    read += n;
  }
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

  sleep(100);

  functionality(&socket);

  sleep(100);

  ut_close(&socket);
  return EXIT_SUCCESS;
}
