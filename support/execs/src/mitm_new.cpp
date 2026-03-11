/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

// This creates a lossy wire for our reliability testing.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <mutex>  // std::mutex
#include <queue>  // std::queue
#include <thread>
#include <vector>

#define BUF_SIZE 4096
#define LOCAL_ADDR "127.0.0.1"
#define INITIATOR_PORT 15441
#define LISTENER_PORT 12000

using namespace std;

struct queuenode {
  long dequeue_time;
  char buffer[BUF_SIZE];
  uint16_t n;
};

std::mutex listen_mtx;
std::queue<struct queuenode *> listen_queue;

std::mutex initiator_mtx;
std::queue<struct queuenode *> initiator_queue;

struct sockaddr_in mitm_addr;
struct sockaddr_in listener_addr;
struct sockaddr_in initiator_addr;
struct sockaddr_in cli_addr;
int die_flag = 0;
int mitm_fd;

void send_packets() {
  struct queuenode *CurrNode;
  long now;
  timeval time;

  while (!die_flag) {
    gettimeofday(&time, NULL);
    now = (time.tv_sec * 1000) + (time.tv_usec / 1000);

    listen_mtx.lock();
    CurrNode = listen_queue.front();

    while (CurrNode->dequeue_time <= now) {
      listen_queue.pop();
      sendto(mitm_fd, CurrNode->buffer, CurrNode->n, MSG_CONFIRM,
             (const struct sockaddr *)&listener_addr, sizeof(listener_addr));
      delete (CurrNode);
      CurrNode = listen_queue.front();
    }

    listen_mtx.unlock();

    initiator_mtx.lock();

    CurrNode = initiator_queue.front();
    while (CurrNode->dequeue_time <= now) {
      initiator_queue.pop();
      sendto(mitm_fd, CurrNode->buffer, CurrNode->n, MSG_CONFIRM,
             (const struct sockaddr *)&initiator_addr, sizeof(initiator_addr));
      delete (CurrNode);
      CurrNode = initiator_queue.front();
    }

    initiator_mtx.unlock();
  }
}

int main(int argc, char *argv[]) {
  int loss;
  int value = 1;
  unsigned int len;
  int found_initiator;
  int prob;
  long now;
  long latency = 50;
  std::thread relay_packet;
  timeval time;

  struct queuenode *CurrNode;

  // Set up args
  if (argc == 1) {
    loss = 0;
  } else if (argc == 2) {
    loss = (int)(100 * atof(argv[1]));
  } else {
    printf("Incorrect number of args\n");
    return -1;
  }

  relay_packet = std::thread(send_packets);

  // Construct mitm address
  mitm_fd = socket(AF_INET, SOCK_DGRAM, 0);
  memset(&mitm_addr, 0, sizeof(mitm_addr));
  mitm_addr.sin_family = AF_INET;
  mitm_addr.sin_addr.s_addr = inet_addr(LOCAL_ADDR);
  mitm_addr.sin_port = htons(INITIATOR_PORT);

  // Allow for reuse of mitm addr
  setsockopt(mitm_fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));

  // Construct listener address
  memset(&listener_addr, 0, sizeof(listener_addr));
  listener_addr.sin_family = AF_INET;
  listener_addr.sin_addr.s_addr = inet_addr(LOCAL_ADDR);
  listener_addr.sin_port = htons(LISTENER_PORT);

  // Bind to mitm addr
  bind(mitm_fd, (struct sockaddr *)&mitm_addr, sizeof(mitm_addr));

  len = sizeof(cli_addr);
  memset(&cli_addr, 0, sizeof(cli_addr));
  memset(&initiator_addr, 0, sizeof(initiator_addr));

  while (1) {
    CurrNode = new queuenode();
    CurrNode->n = recvfrom(mitm_fd, (char *)CurrNode->buffer, BUF_SIZE,
                           MSG_WAITALL, (struct sockaddr *)&cli_addr, &len);

    gettimeofday(&time, NULL);
    now = (time.tv_sec * 1000) + (time.tv_usec / 1000);

    CurrNode->dequeue_time = now + latency;

    if (CurrNode->n <= 0) {
      delete (CurrNode);
      die_flag = 1;
      break;
    }

    // if pkt came from initiator
    prob = rand() % 100;

    // Setup initiator information
    if (found_initiator == 0 && cli_addr.sin_port != listener_addr.sin_port) {
      // copy cli_addr into initiator
      memcpy(&initiator_addr, &cli_addr, sizeof(cli_addr));
      found_initiator = 1;
    }

    if (cli_addr.sin_port != listener_addr.sin_port) {
      // check prob and sendto listener
      if (prob >= loss) {
        listen_mtx.lock();
        listen_queue.push(CurrNode);
        listen_mtx.unlock();
      }
    } else if (found_initiator != 0) {
      // check prob and sendto initiator
      if (prob >= loss) {
        initiator_mtx.lock();
        initiator_queue.push(CurrNode);
        initiator_mtx.unlock();
      }
    }
  }
  // Wait for thread to join
  relay_packet.join();
  return 0;
}
