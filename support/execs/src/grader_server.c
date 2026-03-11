/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ut_tcp.h"
#include "consts.h"

#define BUF_SIZE 30000

void functionality(ut_socket_t *sock) {
  char buf[BUF_SIZE];
  int n;
  int file_length = 1048576;
  int read = 0;
  FILE *fp;

  fp = fopen(SUPPORT_PATH "grader_1M_file_received", "wb");
  while (read < file_length) {
    n = ut_read(sock, buf, BUF_SIZE, NO_FLAG);
    fwrite(buf, 1, n, fp);
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

  printf("STARTING SERVER on port %d\n", portno);

  if (ut_socket(&socket, TCP_LISTENER, portno, serverip) < 0) {
    printf("FAILED TO CREATE SOCKET\n");
    exit(EXIT_FAILURE);
  }

  functionality(&socket);

  sleep(100);

  ut_close(&socket);
  return EXIT_SUCCESS;
}
