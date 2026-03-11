# Copyright (C) 2022 Carnegie Mellon University
# Copyright (C) 2025 University of Texas at Austin
#
# No part of the project may be copied and/or distributed without the express
# permission of the course staff.

import socket
import subprocess
import time
import unittest
from contextlib import contextmanager
from typing import Callable, Optional

from gradescope_utils.autograder_utils.decorators import number, partial_credit

from test_support import before, my_scapy
from test_support.config import ACK_MASK, UTCSTCP, MSS, get_utcs, TIMEOUT
from test_support.constants import GRADER_SENDER
from test_support.open_conns import connection_passive_open, get_free_port


class Receiver:
    def __init__(
        self,
        advertised_window: int = 2**16 - 1,
        ack_delay: float = 0.5,
        verbose: bool = True,
    ) -> None:
        self.verbose = verbose
        self.ack_delay = ack_delay

        if self.verbose:
            self.stdout = None
            self.stderr = None
        else:
            self.stdout = subprocess.DEVNULL
            self.stderr = subprocess.DEVNULL

        self.src_port = get_free_port()
        self.advertised_window = advertised_window

    @contextmanager
    def start_receiver(self):
        try:
            p = subprocess.Popen(
                [GRADER_SENDER, str(self.src_port)],
                stdout=self.stdout,
                stderr=self.stderr,
            )
            ret = connection_passive_open(
                receive_window=self.advertised_window, dst_port=self.src_port
            )
            self.rcv_next, self.snd_next, _, self.dst_port = ret

            if self.rcv_next is None:
                print(
                    "Failed to establish connection with sender in the handshake"
                    " process"
                )
                raise RuntimeError

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(("127.0.0.1", self.src_port))
            self.sock.setblocking(False)

            self.last_ack = None
            time.sleep(1)

            yield p
        finally:
            self.sock.close()
            p.terminate()
            p.wait()

    def discard_received(self, max_pkts: int = 1000) -> None:
        _, _ = my_scapy.sniff(max_pkts, 0.1, sock=self.sock)

    def send_ack(self) -> None:
        ack_pkt = UTCSTCP(
            plen=23,
            source_port=self.src_port,
            destination_port=self.src_port,
            advertised_window=self.advertised_window,
            seq_num=self.snd_next,
            flags=ACK_MASK,
            ack_num=self.last_ack,
        )

        self.sock.sendto(bytes(ack_pkt), ("127.0.0.1", self.dst_port))

    def measure_sending_window(
        self, nb_windows: int, get_max_pkts: Callable = lambda x : 2 ** x, timeout: float = 0.2
    ) -> Optional[list[int]]:
        window_pkts = []
        window_sizes = []
        last_window_ack = None
        for window_idx in range(nb_windows):
            window_pkts, _ = my_scapy.sniff(get_max_pkts(window_idx), timeout, sock=self.sock)

            if len(window_pkts) == 0:
                if len(window_sizes) == 0:
                    print("Did not receive data packet from the sender.")
                else:
                    print(f"Did not receive data after {len(window_sizes)} " "windows.")
                return None

            smallest_seq: int = window_pkts[0].seq_num

            payload_len = len(window_pkts[0].payload)
            largest_seq: int = window_pkts[0].seq_num + payload_len

            for pkt in window_pkts:
                pkt = get_utcs(pkt)
                if pkt is None:
                    continue

                payload_len = len(pkt.payload)

                if before(pkt.seq_num, smallest_seq):
                    smallest_seq = pkt.seq_num
                if before(largest_seq, pkt.seq_num + payload_len):
                    largest_seq = pkt.seq_num + payload_len

                ack = (pkt.seq_num + payload_len) & 0xFFFFFFFF

                if last_window_ack is None or before(last_window_ack, ack):
                    last_window_ack = ack
                    if self.last_ack is None or before(self.last_ack, ack):
                        self.last_ack = ack

                    self.send_ack()

            bytes_in_window = (largest_seq - smallest_seq) & 0xFFFFFFFF
            window_sizes.append(bytes_in_window)

        return window_sizes


class TestCases(unittest.TestCase):
    def setUp(self) -> None:
        self.startTime = time.time()

    def tearDown(self) -> None:
        t = time.time() - self.startTime
        print("Duration of %s: %.3fs" % (self.id(), t))

    @partial_credit(10.0)
    @number("5.1")
    def test_slow_start(self, set_score: Callable) -> None:
        print(
            "Congestion control test - this test checks if the congestion "
            "window increases exponentially during slow start."
        )
        receiver = Receiver()
        score = 0.0
        try:
            with receiver.start_receiver():
                window_sizes = receiver.measure_sending_window(6, timeout=1)

            if window_sizes is None:
                set_score(score)
                return

            previous_window_size = MSS
            for i, window_size in enumerate(window_sizes[1:]):
                print(
                    f"  {i}: {window_size} bytes - {window_size / previous_window_size:.2f}x"
                )
                lower_bound = 1.8 * previous_window_size
                upper_bound = 2.2 * previous_window_size
                if not (lower_bound < window_size < upper_bound):
                    print(
                        "Congestion window did not increase exponentially during"
                        " slow start or started with the wrong size. Make sure"
                        " to set the initial congestion window to"
                        " WINDOW_INITIAL_WINDOW_SIZE."
                    )
                    set_score(score)
                    return
                score += 2.0

                previous_window_size = window_size
            set_score(score)
        except RuntimeError:
            set_score(0.0)

    @partial_credit(10.0)
    @number("5.2")
    def test_cwnd_grows_after_slow_start(self, set_score: Callable) -> None:
        print(
            "Congestion control test - this test checks if the "
            "implementation returns to slow start on timeout."
        )
        receiver = Receiver(verbose=True)
        score = 0.0

        try:
            with receiver.start_receiver():
                # This assumes that WINDOW_INITIAL_SSTHRESH is MSS * 32. Which means
                # that it should exit slow start at the 6th window. We must make sure
                # that we consider the windows after that.
                window_sizes = receiver.measure_sending_window(6)
                if window_sizes is None:
                    set_score(score)
                    return

                window_sizes = receiver.measure_sending_window(5, get_max_pkts=lambda x: 1000, timeout=0.2)
                if window_sizes is None:
                    set_score(score)
                    return

                prev_max_pkts = 2 ** 5
                previous_window_size = prev_max_pkts * MSS
                for window_size in window_sizes:
                    lower_bound = (previous_window_size + MSS) * 0.9
                    upper_bound = (previous_window_size + MSS) * 1.1
                    if not (lower_bound < window_size < upper_bound):
                        print(
                            "Congestion window did not increase by approximately MSS after exiting slow start. "
                            "Make sure to increase the congestion window by approximately MSS every round trip time after exiting slow start."
                        )
                    previous_window_size = window_size
                    score += 2.0
                set_score(score)

        except RuntimeError:
            set_score(0.0)


    @partial_credit(10.0)
    @number("5.3")
    def test_goes_to_slow_start_on_timeout(self, set_score: Callable) -> None:
        print(
            "Congestion control test - this test checks if the "
            "implementation returns to slow start on timeout."
        )
        receiver = Receiver(verbose=False)
        try:
            with receiver.start_receiver():
                # This assumes that WINDOW_INITIAL_SSTHRESH is MSS * 64. Which means
                # that it should exit slow start at the 6th window. We must make sure
                # that we consider the windows after that.
                window_sizes = receiver.measure_sending_window(6)
                if window_sizes is None:
                    set_score(0.0)
                    return

                # Make sure it times out.
                finish_wait = time.time() + 3.0
                print("Forcing timeout...")
                while time.time() < finish_wait:
                    receiver.discard_received()

                print("After timeout:")
                window_sizes = receiver.measure_sending_window(2, timeout=3.0)

            if window_sizes is None:
                set_score(0.0)
                return

            window_size_after = min(window_sizes)
            if window_size_after >= MSS * 2:
                print("Implementation did not return to slow start after a timeout.")
                set_score(0.0)
                return

            print("Congestion window decreased significantly after timeout.")
            set_score(10.0)

        except RuntimeError:
            set_score(0.0)

    @partial_credit(10.0)
    @number("5.4")
    def test_fast_recovery(self, set_score: Callable) -> None:
        print(
            "Congestion control test - this test checks if the "
            "implementation enters fast recovery on 3 duplicate ACKs."
        )
        receiver = Receiver(verbose=True)

        try:
            with receiver.start_receiver():
                # First, let the sender establish a window
                print("Initial slow start phase...")
                window_sizes = receiver.measure_sending_window(6, timeout=1)

                if window_sizes is None:
                    print("Failed to receive initial windows")
                    set_score(0.0)
                    return

                # Get the last window size before triggering fast recovery
                last_window_size = window_sizes[-1]
                print(f"Last window size before duplicate ACKs: {last_window_size} bytes")

                # Expected values after fast recovery
                expected_ssthresh = last_window_size / 2
                expected_cwnd = expected_ssthresh + 3 * MSS
                print(f"Expected cwnd after fast recovery: {expected_cwnd} bytes")

                # Now send 3 duplicate ACKs to trigger fast recovery
                print("Sending 3 duplicate ACKs to trigger fast recovery...")
                saved_ack = receiver.last_ack

                # Send duplicate ACKs
                for i in range(3):
                    receiver.last_ack = saved_ack
                    receiver.send_ack()
                    time.sleep(0.1)

                # Small delay to let fast recovery take effect
                time.sleep(0.5)

                # Now measure the window after fast recovery
                print("Measuring window after fast recovery...")
                # We expect fast retransmit to happen, then window should be
                # approximately ssthresh + 3*MSS
                window_sizes_after = receiver.measure_sending_window(
                    1,
                    get_max_pkts=lambda x: max(1, int(expected_cwnd / MSS)),
                    timeout=1.0
                )

                if window_sizes_after is None:
                    print("Failed to receive windows after fast recovery")
                    set_score(0.0)
                    return

                window_after_fast_recovery = window_sizes_after[0]
                print(f"Window size after fast recovery: {window_after_fast_recovery} bytes")

                # Check if the window size is approximately equal to ssthresh + 3*MSS
                # Allow for some variance due to timing and implementation details
                lower_bound = expected_cwnd - 2 * MSS
                upper_bound = expected_cwnd + 2 * MSS

                if lower_bound <= window_after_fast_recovery <= upper_bound:
                    print(
                        f"Fast recovery successful! Window adjusted from {last_window_size} "
                        f"to {window_after_fast_recovery} bytes (expected ~{expected_cwnd} bytes)"
                    )
                    set_score(10.0)
                else:
                    print(
                        f"Fast recovery did not adjust window correctly. "
                        f"Expected ~{expected_cwnd} bytes, got {window_after_fast_recovery} bytes. "
                        f"Make sure ssthresh = cwnd/2 and cwnd = ssthresh + 3*MSS on 3 duplicate ACKs."
                    )
                    set_score(0.0)

        except RuntimeError:
            set_score(0.0)
