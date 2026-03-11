/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

#ifndef PROJECT_2_15_441_INC_GRADING_H_
#define PROJECT_2_15_441_INC_GRADING_H_


/*
 * DO NOT CHANGE THIS FILE
 * This contains the variables for your TCP implementation
 * and we will replace this file during the autolab testing with new variables.
 */

// packet lengths
#define MAX_LEN 1400
#define MY_MSS (MAX_LEN - sizeof(ut_tcp_header_t))

// window variables
#define CP1_WINDOW_SIZE (MY_MSS * 32)
#define WINDOW_INITIAL_WINDOW_SIZE MY_MSS
#define WINDOW_INITIAL_SSTHRESH (MY_MSS * 32)

// retransmission timeout
#define DEFAULT_TIMEOUT 200  // ms

// max TCP buffer
#define MAX_NETWORK_BUFFER 65535  // (2^16 - 1) bytes

#endif  // PROJECT_2_15_441_INC_GRADING_H_
