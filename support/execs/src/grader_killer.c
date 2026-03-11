/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

#include <stdlib.h>
#include <unistd.h>

#include "ut_tcp.h"

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

  sleep(1);
  if (ut_socket(&socket, TCP_INITIATOR, portno, serverip) < 0)
    exit(EXIT_FAILURE);

  sleep(1);

  ut_close(&socket);
  return EXIT_SUCCESS;
}
