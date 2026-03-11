/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ut_tcp.h"
#include "consts.h"

#define BUF_SIZE 9898

void functionality(ut_socket_t *sock) {
  char buf[BUF_SIZE];
  int bytes_read;
  FILE *fp;

  sleep(1);

  fp = fopen(SUPPORT_PATH "grader_200KB_file", "rb");
  while ((bytes_read = fread(buf, 1, BUF_SIZE, fp)) > 0) {
    ut_write(sock, buf, bytes_read);
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

  sleep(1);

  if (ut_socket(&socket, TCP_INITIATOR, portno, serverip) < 0)
    exit(EXIT_FAILURE);

  functionality(&socket);

  sleep(100);

  ut_close(&socket);
  return EXIT_SUCCESS;
}
