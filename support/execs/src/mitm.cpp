/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include "ut_packet.h"


int main(int argc, const char *argv[]) {
  if (argc != 1 && argc != 3 && argc != 5) {
    std::cerr << "Incorrect number of args" << std::endl;
    return -1;
  }

  int loss;
  float latency;
  int server_port;
  int client_port;

  // Set up args.
  if (argc == 3) {
    server_port = atoi(argv[1]);
    client_port = atoi(argv[2]);
    loss = 0;
    latency = 0.0;
  }

  if (argc == 5) {
    server_port = atoi(argv[1]);
    client_port = atoi(argv[2]);
    loss = (int)(100 * atof(argv[3]));
    latency = (float)(atof(argv[4]));
  } else {
    server_port = 12000;
    client_port = 15441;
    loss = 0;
    latency = 0.0;
  }

  printf("Loss %d\n", loss);

  // Construct mitm address.
  struct sockaddr_in mitm_addr;
  int mitm_fd = socket(AF_INET, SOCK_DGRAM, 0);
  memset(&mitm_addr, 0, sizeof(mitm_addr));
  mitm_addr.sin_family = AF_INET;
  mitm_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  mitm_addr.sin_port = htons(client_port);

  // Allow for reuse of mitm addr.
  int value = 1;
  setsockopt(mitm_fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));

  // Set timeout for mitm socket.
  struct timeval timeout;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  setsockopt(mitm_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
             sizeof(timeout));
  setsockopt(mitm_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
             sizeof(timeout));

  // Construct listener address.
  struct sockaddr_in listener_addr;
  int listener_fd = socket(AF_INET, SOCK_DGRAM, 0);
  memset(&listener_addr, 0, sizeof(listener_addr));
  listener_addr.sin_family = AF_INET;
  listener_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  listener_addr.sin_port = htons(server_port);

  // Allow for reuse of listener addr.
  setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));

  // Set timeout for listener socket.
  setsockopt(listener_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
             sizeof(timeout));
  setsockopt(listener_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
             sizeof(timeout));

  // Bind to mitm addr.
  bind(mitm_fd, (struct sockaddr *)&mitm_addr, sizeof(mitm_addr));

  uint16_t n;
  char buffer[4096];
  struct sockaddr_in cli_addr;
  unsigned int len = sizeof(cli_addr);
  memset(&cli_addr, 0, sizeof(cli_addr));
  struct sockaddr_in initiator_addr;
  memset(&initiator_addr, 0, sizeof(initiator_addr));
  int found_initiator = 0;

  srand(time(NULL));
  int prob;

  std::chrono::milliseconds timespan(static_cast<int>(latency * 1000));

  while (1) {
    n = recvfrom(mitm_fd, (char *)buffer, 4096, MSG_WAITALL,
                 (struct sockaddr *)&cli_addr, &len);
    if (n <= 0) {
      break;
    }

    ut_tcp_header_t* hdr = (ut_tcp_header_t*)buffer;

    // If pkt came from initiator.
    prob = rand() % 100;
    if (cli_addr.sin_port != listener_addr.sin_port) {
      // Copy cli_addr into initiator.
      memcpy(&initiator_addr, &cli_addr, sizeof(cli_addr));
      found_initiator = 1;
      hdr->destination_port = listener_addr.sin_port;

      // Check prob and sendto listener.
      if (prob >= loss) {
        // is len correct?
        std::this_thread::sleep_for(timespan);
        sendto(mitm_fd, buffer, n, MSG_CONFIRM,
               (const struct sockaddr *)&listener_addr, sizeof(listener_addr));
      }
    } else {
      // If initiator does not exist, drop pkt.
      if (!found_initiator) {
        continue;
      }
      hdr->destination_port = initiator_addr.sin_port;

      // Check prob and sendto initiator.
      if (prob >= loss) {
        std::this_thread::sleep_for(timespan);
        sendto(mitm_fd, buffer, n, MSG_CONFIRM,
               (const struct sockaddr *)&initiator_addr,
               sizeof(initiator_addr));
      }
    }
  }

  return 0;
}
