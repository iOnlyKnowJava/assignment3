/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ut_tcp.h"
#include "consts.h"

#define BUF_SIZE 9000

void functionality(ut_socket_t *sock) {
  char buf[BUF_SIZE];
  int bytes_read;
  FILE *fp;

  fp = fopen(SUPPORT_PATH "grader_50K_file", "rb");
  while ((bytes_read = fread(buf, 1, BUF_SIZE, fp)) > 0) {
    ut_write(sock, buf, bytes_read);
  }
  fclose(fp);

  sleep(10);
}

int main(int argc, char **argv) {
  int portno;
  char *serverip;
  ut_socket_t socket;

  serverip = "127.0.0.1";

  if (argc > 1) {
    portno = atoi(argv[1]);
  } else {
    portno = 15441;
  }

  if (ut_socket(&socket, TCP_INITIATOR, portno, serverip) < 0)
    exit(EXIT_FAILURE);


  functionality(&socket);

  if (ut_close(&socket) < 0) {
    exit(EXIT_FAILURE);
  }
  return EXIT_SUCCESS;
}
