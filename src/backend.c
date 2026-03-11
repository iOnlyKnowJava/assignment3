/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

#include "backend.h"

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "ut_packet.h"
#include "ut_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

void send_empty(ut_socket_t* sock, int s_flags, bool fin_ack, bool send_fin) {
    size_t conn_len = sizeof(sock->conn);
    int sockfd = sock->socket;

    uint16_t src = sock->my_port;
    uint16_t dst = ntohs(sock->conn.sin_port);

    uint32_t seq = sock->send_win.last_sent + 1;
    if (send_fin) {
        seq = sock->send_fin_seq;
    }
    uint32_t ack = sock->recv_win.next_expect;
    if (fin_ack) {
        ack = sock->recv_fin_seq + 1;
    }

    uint16_t hlen = sizeof(ut_tcp_header_t);
    uint8_t flags = s_flags;
    uint16_t adv_window = MAX_NETWORK_BUFFER + sock->recv_win.last_read - sock->recv_win.last_recv;
    uint16_t payload_len = 0;
    uint8_t* payload = &flags;
    uint16_t plen = hlen + payload_len;

    uint8_t* msg = create_packet(
        src, dst, seq, ack, hlen, plen, flags, adv_window, payload, payload_len);
    sendto(sockfd, msg, plen, 0, (struct sockaddr*)&(sock->conn), conn_len);
    free(msg);
}

bool check_dying(ut_socket_t* sock) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    bool dying = sock->dying;
    if (dying) {
        while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
        }
        if (sock->sending_len == 0) {
            sock->send_fin_seq = sock->send_win.last_write + 1;
        } else {
            dying = false;
        }
        pthread_mutex_unlock(&(sock->send_lock));
    }
    pthread_mutex_unlock(&(sock->death_lock));
    return dying;
}

void handle_pkt_handshake(ut_socket_t* sock, ut_tcp_header_t* hdr) {
    /*
    TODOs:
    * The `handle_pkt_handshake` function processes TCP handshake packets for a given socket.
    * It first extracts the flags from the TCP header and determines whether the socket is an initiator or a listener.
    * If the socket is an initiator, it verifies the SYN-ACK response and updates the send and receive windows accordingly.
    * If the socket is a listener, it handles incoming SYN packets and ACK responses, updating the socket’s state and windows as needed.
    */
    sock->send_adv_win = get_advertised_window(hdr);
    if (sock->type == TCP_INITIATOR) {
        if ((get_flags(hdr) & SYN_FLAG_MASK) && (get_flags(hdr) & ACK_FLAG_MASK) && (get_ack(hdr) - 1 == sock->send_win.last_sent + 1)) {
            sock->recv_win.last_read = sock->recv_win.last_recv = get_seq(hdr);
            sock->recv_win.next_expect = get_seq(hdr) + 1;
            sock->send_win.last_ack = sock->send_win.last_sent = sock->send_win.last_write = get_ack(hdr) - 1;
            sock->send_syn = false;
        }
    } else {
        if (get_flags(hdr) & SYN_FLAG_MASK) {
            sock->recv_win.last_read = sock->recv_win.last_recv = get_seq(hdr);
            sock->recv_win.next_expect = get_seq(hdr) + 1u;
            sock->send_syn = true;
        } else if ((get_flags(hdr) & ACK_FLAG_MASK) && (get_ack(hdr) - 1 == sock->send_win.last_sent + 1)) {
            sock->send_win.last_ack = sock->send_win.last_sent = sock->send_win.last_write = get_ack(hdr) - 1;
            sock->complete_init = true;
            pthread_cond_signal(&(sock->wait_cond));
        }
    }
}

void handle_ack(ut_socket_t* sock, ut_tcp_header_t* hdr) {
    if (after(get_ack(hdr) - 1, sock->send_win.last_ack)) {
        while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
        }
        /*
        TODOs:
        * Reset duplicated ACK count to zero.
        * Update the congestion window.
        * Update the sender window based on the ACK field.
          * Update `last_ack`, re-allocate the sending buffer, and update the `sending_len` field.
        */
        if (sock->dup_ack_count >= 3) {
            // printf("A");
            sock->cong_win = sock->slow_start_thresh;
        } else {
            // printf("\nB %d %d\n",sock->cong_win,sock->slow_start_thresh);
            sock->cong_win += (sock->cong_win <= sock->slow_start_thresh) ? MSS : MSS * MSS / sock->cong_win;
        }
        sock->dup_ack_count = 0;
        if (after(get_ack(hdr) - 1, sock->send_win.last_ack)) {
            uint32_t prev_ack = sock->send_win.last_ack;
            sock->send_win.last_ack = get_ack(hdr) - 1;
            sock->sending_len = sock->send_win.last_write - sock->send_win.last_ack;
            if (sock->sending_len) {
                uint8_t* temp = malloc(sock->sending_len);
                memcpy(temp, sock->sending_buf + sock->send_win.last_ack - prev_ack, sock->sending_len);
                free(sock->sending_buf);
                sock->sending_buf = temp;
            } else {
                if (sock->sending_buf) {
                    free(sock->sending_buf);
                    sock->sending_buf = NULL;
                }
            }
        }
        pthread_mutex_unlock(&(sock->send_lock));
    }
    // Handle Duplicated ACK.
    else if (get_ack(hdr) - 1 == sock->send_win.last_ack) {
        /*
        TODOs:
        * Increment the duplicated ACK count (sock->dup_ack_count).
        * If the duplicated ACK count reaches 3, adjust the congestion window and slow start threshold.
          * i.e., Transit to "Fast recovery" state.
          * Make sure to retransmit missing segments using Go-back-N (i.e., update the `last_sent` to `last_ack`).
        * If the duplicated ACK count is larger than 3, increment the congestion window by MSS (i.e., "Fast recovery" state).
        */
        sock->dup_ack_count++;
        if (sock->dup_ack_count == 3) {
            sock->slow_start_thresh = sock->cong_win / 2;
            sock->cong_win = sock->slow_start_thresh + 3 * MSS;
            sock->send_win.last_sent = sock->send_win.last_ack;
        } else if (sock->dup_ack_count > 3) {
            sock->cong_win += MSS;
        }
    }
}

void add_recv_seg(ut_socket_t* sock, uint32_t start, uint32_t end) {
    recv_seg_t* seg = malloc(sizeof(recv_seg_t));
    seg->start = start;
    seg->end = end;
    seg->next = sock->recv_segs;
    sock->recv_segs = seg;
}

void merge_recv_segs(ut_socket_t* sock) {
    int merged = 1;
    while (merged) {
        merged = 0;
        recv_seg_t** pp = &sock->recv_segs;
        while (*pp) {
            recv_seg_t* seg = *pp;
            if (before(seg->start, sock->recv_win.next_expect) || seg->start == sock->recv_win.next_expect) {
                if (after(seg->end, sock->recv_win.next_expect) || seg->end == sock->recv_win.next_expect) {
                    sock->recv_win.next_expect = seg->end + 1;
                    merged = 1;
                }
                *pp = seg->next;
                free(seg);
            } else {
                pp = &seg->next;
            }
        }
    }
}

void update_received_buf(ut_socket_t* sock, uint8_t* pkt) {
    /*
    - This function processes an incoming TCP packet by updating the receive buffer based on the packet's sequence number and payload length.
    - If the new data extends beyond the last received sequence, it reallocates the receive buffer and copies the payload into the correct position.

    TODOs:
    * Extract the TCP header and sequence number from the packet.
    * Determine the end of the data segment and update the receive window if needed.
    * Copy the payload into the receive buffer based on the sequence number:
      * Ensure that the required buffer space does not exceed `MAX_NETWORK_BUFFER` before proceeding.
      * Use `memcpy` to copy the payload:
        memcpy(void *to, const void *from, size_t numBytes);
    * Send an acknowledgment if the packet arrives in order:
      * Use the `send_empty` function to send the acknowledgment.
    * Handle out-of-order packets by adding them to the list of received segments:
      * Use the `add_recv_seg` function to add the segment when the packet is out-of-order.
      * Merge any overlapping segments by calling `merge_recv_segs` when necessary.
    */
    ut_tcp_header_t* hdr = (ut_tcp_header_t*)pkt;
    uint32_t potential_end = before(sock->recv_win.last_read + MAX_NETWORK_BUFFER, get_seq(hdr) + get_payload_len(pkt) - 1) ? sock->recv_win.last_read + MAX_NETWORK_BUFFER : get_seq(hdr) + get_payload_len(pkt) - 1;
    if (get_payload_len(pkt) == 0 || potential_end + 1 < sock->recv_win.next_expect || get_seq(hdr) > sock->recv_win.last_read + MAX_NETWORK_BUFFER) {
        if (get_payload_len(pkt)) {
            send_empty(sock, ACK_FLAG_MASK, false, false);
        }
        return;
    }

    uint32_t new_end = after(potential_end, sock->recv_win.last_recv) ? potential_end : sock->recv_win.last_recv;
    sock->recv_win.last_recv = new_end;
    if (sock->recv_win.last_recv != sock->recv_win.last_read) {
        sock->received_buf = realloc(sock->received_buf, sock->recv_win.last_recv - sock->recv_win.last_read);
        // printf("%d\n", sock->recv_win.last_recv - sock->recv_win.last_read);
    } else {
        // printf("%d %d\n", sock->recv_win.last_recv, sock->recv_win.last_read);
        if (sock->received_buf) {
            free(sock->received_buf);
            sock->received_buf = NULL;
        }
    }
    if (sock->received_buf) {
        uint32_t seq = get_seq(hdr);
        uint32_t num = get_payload_len(hdr);
        if (seq < sock->recv_win.last_read + 1) {
            num -= sock->recv_win.last_read + 1 - seq;
            seq = sock->recv_win.last_read + 1;
        }
        memcpy(sock->received_buf + seq - sock->recv_win.last_read - 1u, get_payload(pkt), MIN(num, sock->recv_win.last_recv - seq + 1u));
    }

    if (get_seq(hdr) == sock->recv_win.next_expect) {
        sock->recv_win.next_expect = potential_end + 1;
    } else {
        add_recv_seg(sock, after(get_seq(hdr),sock->recv_win.last_read+1)?get_seq(hdr):sock->recv_win.last_read+1, potential_end);
    }
    merge_recv_segs(sock);
    send_empty(sock, ACK_FLAG_MASK, false, false);
    sock->received_len = sock->recv_win.next_expect - sock->recv_win.last_read - 1;
}

void handle_pkt(ut_socket_t* sock, uint8_t* pkt) {
    ut_tcp_header_t* hdr = (ut_tcp_header_t*)pkt;
    uint8_t flags = get_flags(hdr);
    if (!sock->complete_init) {
        handle_pkt_handshake(sock, hdr);
        return;
    }

    /*
    TODOs:
    * Handle the FIN flag.
    * Mark the socket as having received a FIN, store the sequence number, and send an ACK response.

    * Update the advertised window.
    * Handle the ACK flag. You will have to handle the following cases:
    1) ACK after sending FIN.
    * If the ACK is for the FIN sequence and ready to finish, mark the socket as FIN-ACKed.
    * `check_dying` function can be useful to check whether the socket is in the dying state.
    2) ACK after sending data.
    * If the ACK is for a new sequence, update the send window and congestion control (call `handle_ack`).
    * Update the receive buffer (call `update_received_buf`).
    */
    sock->send_adv_win = get_advertised_window(hdr);
    if (flags & FIN_FLAG_MASK) {
        sock->recv_fin = true;
        sock->recv_fin_seq = get_seq(hdr);
        send_empty(sock, ACK_FLAG_MASK, true, false);
        return;
    }
    if (flags & ACK_FLAG_MASK) {
        if (check_dying(sock) && get_ack(hdr) == sock->send_fin_seq + 1) {
            sock->fin_acked = true;
        } else {
            handle_ack(sock, hdr);
        }
    }
    update_received_buf(sock, pkt);
}

void recv_pkts(ut_socket_t* sock) {
    ut_tcp_header_t hdr;
    uint8_t* pkt;
    socklen_t conn_len = sizeof(sock->conn);
    ssize_t len = 0, n = 0;
    uint32_t plen = 0, buf_size = 0;

    struct pollfd ack_fd;
    ack_fd.fd = sock->socket;
    ack_fd.events = POLLIN;
    if (poll(&ack_fd, 1, DEFAULT_TIMEOUT) <= 0) {  // TIMEOUT
        /*
        TODOs:
        * Reset duplicated ACK count to zero.
        * Implement the rest of timeout handling
          * Congestion control window and slow start threshold adjustment
          * Adjust the send window for retransmission of lost packets (Go-back-N)
        */
        // printf("E");
        sock->dup_ack_count = 0;
        sock->slow_start_thresh = sock->cong_win / 2;
        sock->cong_win = MSS;
        sock->send_win.last_sent = sock->send_win.last_ack;
        return;
    }

    while (1) {
        conn_len = sizeof(sock->conn);
        len = recvfrom(sock->socket, &hdr, sizeof(ut_tcp_header_t),
                       MSG_DONTWAIT | MSG_PEEK, (struct sockaddr*)&(sock->conn),
                       &conn_len);

        if (len < (ssize_t)sizeof(ut_tcp_header_t))
            break;

        plen = get_plen(&hdr);
        pkt = malloc(plen);
        buf_size = 0;
        while (buf_size < plen) {
            n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                         (struct sockaddr*)&(sock->conn), &conn_len);
            buf_size = buf_size + n;
        }
        while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
        }
        handle_pkt(sock, pkt);
        pthread_mutex_unlock(&(sock->recv_lock));
        free(pkt);
    }
}

void send_pkts_handshake(ut_socket_t* sock) {
    /*
    TODOs:
    * Implement the handshake initialization logic.
    * We provide an example of sending a SYN packet by the initiator below:
    */
    if (sock->type == TCP_INITIATOR) {
        if (sock->send_syn) {
            send_empty(sock, SYN_FLAG_MASK, false, false);
        } else {
            send_empty(sock, ACK_FLAG_MASK, false, false);
            sock->complete_init = true;
            pthread_cond_signal(&(sock->wait_cond));
        }
    } else if (sock->send_syn) {
        send_empty(sock, SYN_FLAG_MASK | ACK_FLAG_MASK, false, false);
    }
}

void send_pkts_data(ut_socket_t* sock) {
    /*
    * Sends packets of data over a TCP connection.
    * This function handles the transmission of data packets over a TCP connection
      using the provided socket. It ensures that the data is sent within the constraints
      of the congestion window, advertised window, and maximum segment size (MSS).

    TODOs:
    * Calculate the available window size for sending data based on the congestion window,
      advertised window, and the amount of data already sent.
      * Make sure to handle when the advertised window is zero (i.e., zero-window probing).
    * Iterate the following steps until the available window size is consumed in the sending buffer:
      * Create and send packets with appropriate sequence and acknowledgment numbers,
        ensuring the payload length does not exceed the available window or MSS.
        * Refer to the send_empty function for guidance on creating and sending packets.
      * Update the last sent sequence number after each packet is sent.
    */
    uint32_t total_send = MIN(sock->cong_win, sock->send_win.last_write - sock->send_win.last_sent);
    if (total_send > 0 && sock->send_adv_win == 0) {
        total_send = 1;
    } else {
        total_send = MIN(total_send, sock->send_adv_win);
    }
    // printf("%d %d\n", sock->cong_win, sock->slow_start_thresh);
    // printf("%d\n", sock->send_adv_win);
    // printf("%u %u %u %u %u %u %u\n", total_send, sock->cong_win, sock->send_win.last_write - sock->send_win.last_sent, sock->send_adv_win, sock->recv_fin, sock->fin_acked,sock->dying);
    printf("%d %d %d %d %d %d %d\n", total_send, sock->send_win.last_ack, sock->send_win.last_sent, sock->send_win.last_write, sock->recv_win.last_read, sock->recv_win.next_expect, sock->recv_win.last_recv);
    // fflush(stdout);
    while (total_send) {
        size_t conn_len = sizeof(sock->conn);
        int sockfd = sock->socket;

        uint16_t src = sock->my_port;
        uint16_t dst = ntohs(sock->conn.sin_port);

        uint32_t seq = sock->send_win.last_sent + 1;
        uint32_t ack = sock->recv_win.next_expect;
        uint16_t hlen = sizeof(ut_tcp_header_t);
        uint16_t adv_window = MAX_NETWORK_BUFFER + sock->recv_win.last_read - sock->recv_win.last_recv;
        uint16_t payload_len = MIN(MSS, total_send);
        if(!sock->sending_buf){
          printf("%d %d %d\n",sock->send_win.last_ack,sock->send_win.last_sent,sock->send_win.last_write);
          exit(2);
        }
        uint8_t* payload = sock->sending_buf + sock->send_win.last_sent - sock->send_win.last_ack;
        uint16_t plen = hlen + payload_len;

        uint8_t* msg = create_packet(
            src, dst, seq, ack, hlen, plen, ACK_FLAG_MASK, adv_window, payload, payload_len);
        sendto(sockfd, msg, plen, 0, (struct sockaddr*)&(sock->conn), conn_len);
        free(msg);
        total_send -= payload_len;
        sock->send_win.last_sent += payload_len;
    }
    // The code below will be used to record the congestion window size for your report.
    char* log_path = getenv("CONG_WIN_LOG_PATH");
    if (log_path != NULL) {
        FILE* log_file = fopen(log_path, "a");
        if (log_file != NULL) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            fprintf(log_file, "timestamp=%ld, cong_win=%u, send_adv_win=%u\n",
                    ts.tv_sec * 1000 + ts.tv_nsec / 1000000, sock->cong_win, sock->send_adv_win);
            fclose(log_file);
        } else {
            perror("Failed to open log file");
        }
    }
}

void send_pkts(ut_socket_t* sock) {
    if (!sock->complete_init) {
        send_pkts_handshake(sock);
    } else {
        // Stop sending when duplicated ACKs are received and not in fast recovery state.
        // However, still allow zero-window probes so the sender can
        // detect when the receiver re-opens its window.
        if (sock->dup_ack_count < 3 && sock->dup_ack_count > 0 && sock->send_adv_win > 0)
            return;
        while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
        }
        send_pkts_data(sock);
        pthread_mutex_unlock(&(sock->send_lock));
    }
}

void* begin_backend(void* in) {
    ut_socket_t* sock = (ut_socket_t*)in;
    int death, buf_len, send_signal;
    uint8_t* data;

    while (1) {
        if (check_dying(sock)) {
            if (!sock->fin_acked) {
                send_empty(sock, FIN_FLAG_MASK, false, true);
            }
        }

        if (sock->fin_acked && sock->recv_fin) {
            // Finish the connection after timeout
            struct timespec current_time;
            clock_gettime(CLOCK_REALTIME, &current_time);
            if (sock->fin_wait_start_time.tv_sec == 0 && sock->fin_wait_start_time.tv_nsec == 0) {
                sock->fin_wait_start_time = current_time;
            } else {
                long elapsed_ms = (current_time.tv_sec - sock->fin_wait_start_time.tv_sec) * 1000 +
                                  (current_time.tv_nsec - sock->fin_wait_start_time.tv_nsec) / 1000000;
                if (elapsed_ms >= DEFAULT_TIMEOUT * 10) {
                    break;
                }
            }
        }
        send_pkts(sock);
        recv_pkts(sock);
        while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
        }
        uint32_t avail = sock->recv_win.next_expect - sock->recv_win.last_read - 1;
        send_signal = avail > 0;
        pthread_mutex_unlock(&(sock->recv_lock));

        if (send_signal) {
            pthread_cond_signal(&(sock->wait_cond));
        }
    }
    pthread_exit(NULL);
    return NULL;
}
