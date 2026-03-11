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
from scapy.all import Raw

from test_support import before, my_scapy
from test_support.config import (
    ACK_MASK,
    UTCSTCP,
    DEFAULT_ISN,
    MSS,
    SNIFF_TIMEOUT,
    SYN_MASK,
    get_utcs,
    get_random_payload,
)
from test_support.constants import GRADER_SENDER, GRADER_WAITER
from test_support.open_conns import (
    connection_active_open,
    connection_passive_open,
    get_free_port,
)

window_sizes = [1377, 1377 * 10, 1377 * 20, 1377 * 30]


@contextmanager
def launch_grader(app_path: str, portno: int):
    p = subprocess.Popen(
        [app_path, str(portno)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        time.sleep(1)
        yield p
    finally:
        p.terminate()
        p.wait()


def check_window_size(window_size: int) -> Optional[bool]:
    port_number = get_free_port()
    with launch_grader(GRADER_SENDER, port_number):
        advertised_window = 2**16 - 1
        nb_pkts_per_window = window_size // 1377

        rcv_next, snd_next, _, src_port = connection_passive_open(
            receive_window=advertised_window, dst_port=port_number
        )

        if rcv_next is None:
            print(
                "Failed to establish connection with sender in the handshake process"
            )
            return None

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", port_number))
        sock.setblocking(False)

        time.sleep(1)

        last_ack = None
        nb_pkts = 100
        pkt_limit = 1

        # To ensure that the sender can adapt to changes in the advertised window
        # after the handshake, we transfer a few packets before changing the window
        # size.
        for i in range(nb_pkts):
            all_pkts = []
            total_bytes = 0
            all_pkts, _ = my_scapy.sniff(1, 0.5, sock=sock)

            for pkt in all_pkts:
                total_bytes += len(pkt.payload)

            if len(all_pkts) == 0:
                sock.close()
                print("Did not receive data packet from the sender.")
                return None

            if len(all_pkts) > pkt_limit:
                sock.close()
                print(f"Got more than {pkt_limit} packets without sending an ACK!")
                return None

            last_window_ack = None
            for data_pkt in all_pkts:
                data_pkt = get_utcs(data_pkt)

                if data_pkt is None:
                    continue

                if (data_pkt.flags & SYN_MASK) == SYN_MASK:
                    ack = data_pkt.seq_num + 1
                else:
                    ack = data_pkt.seq_num + len(data_pkt.payload)

                # The last batch of ACKs should be sent with the new window size.
                if i == nb_pkts - 1:
                    advertised_window = window_size

                if last_window_ack is None or before(last_window_ack, ack):
                    last_window_ack = ack

                    if last_ack is None or before(last_ack, ack):
                        last_ack = ack

                    ack_pkt = UTCSTCP(
                        plen=23,
                        source_port=port_number,
                        destination_port=src_port,
                        advertised_window=advertised_window,
                        seq_num=snd_next,
                        flags=ACK_MASK,
                        ack_num=last_ack,
                    )

                    sock.sendto(bytes(ack_pkt), ("127.0.0.1", src_port))

        data_pkts, _ = my_scapy.sniff(
            nb_pkts_per_window, SNIFF_TIMEOUT, portno=port_number, sock=sock
        )

        sock.close()

        if len(data_pkts) < nb_pkts_per_window:
            print(
                f"Received only {len(data_pkts)} packets, expected at least "
                f"{nb_pkts_per_window}."
            )
            return None

        smallest_seq = data_pkts[0].seq_num
        largest_seq = data_pkts[0].seq_num + len(data_pkts[0].payload)
        for pkt in data_pkts:
            if before(pkt.seq_num, smallest_seq):
                smallest_seq = pkt.seq_num
            if before(largest_seq, pkt.seq_num + len(pkt.payload)):
                largest_seq = pkt.seq_num + len(pkt.payload)

        bytes_in_window = (largest_seq - smallest_seq) & 0xFFFFFFFF

        if bytes_in_window > window_size:
            print(
                f"Received {bytes_in_window} bytes, expected at most " f"{window_size}."
            )
            return False

        return True


class TestCases(unittest.TestCase):
    def setUp(self) -> None:
        self.startTime = time.time()

    def tearDown(self) -> None:
        t = time.time() - self.startTime
        print("Duration of %s: %.3fs" % (self.id(), t))

    @partial_credit(10.0)
    @number("3.1")
    def test_recv_window_change(self, set_score: Callable[[float], None]) -> None:
        print(
            "Flow control test - this test checks if sender correctly "
            "responds to changes in the receiver's advertised window."
        )
        score = 0.0
        for window_size in window_sizes:
            print("-----------------------------------------")
            print(f"Testing advertised window with size {window_size} bytes")
            window_correct = check_window_size(window_size)
            if window_correct is None or window_correct is False:
                break
            score += 10.0 / len(window_sizes)

        set_score(score)

    @partial_credit(10.0)
    @number("3.2")
    def test_recv_window_size(self, set_score: Callable[[float], None]) -> None:
        print(
            "Flow control test - this test checks if the advertised window is "
            "reduced correctly when data is not consumed by the application."
        )
        server_port = get_free_port()
        client_port = get_free_port()
        with launch_grader(GRADER_WAITER, server_port):
            rcv_next, snd_next, _ = connection_active_open(
                isn=DEFAULT_ISN, server_port=server_port, client_port=client_port
            )

            if rcv_next is None or snd_next is None:
                self.fail(
                    "Failed to establish connection with receiver in the "
                    "handshake process"
                )

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", client_port))
            sock.settimeout(float(SNIFF_TIMEOUT) / 2.0)

            windows = []
            payload_size = 1000
            for _ in range(20):
                data = get_random_payload(payload_size)
                packet_len = len(data) + 23
                data_pkt = UTCSTCP(
                    plen=packet_len, seq_num=snd_next, flags=0x0, ack_num=rcv_next
                ) / Raw(load=data)
                snd_next += 1000
                sock.sendto(bytes(data_pkt), ("127.0.0.1", server_port))

                try:
                    data, _ = sock.recvfrom(4096)
                except Exception:
                    data = None

                if data is None or len(data) <= 0:
                    sock.close()
                    self.fail("Did not receive ack for data packet")

                data_pkt = UTCSTCP(data)
                adv_window = get_utcs(data_pkt).advertised_window
                windows.append(adv_window)

            sock.close()
            for i in range(1, 20):
                window_reduction = windows[i - 1] - windows[i]
                if window_reduction != payload_size:
                    self.fail(
                        f"Advertised window was not reduced correctly. Expected "
                        f"{payload_size} bytes window size reduction, got "
                        f"{window_reduction} instead."
                    )
            set_score(10.0)

    def _setup_zero_window_test(self):
        """Helper: connect to GRADER_SENDER, receive and ACK packets to get
        data flowing, then return (port_number, sock, src_port, snd_next,
        last_ack).  Returns None on failure (after calling self.fail)."""
        port_number = get_free_port()
        ctx = launch_grader(GRADER_SENDER, port_number)
        process = ctx.__enter__()

        advertised_window = 2**16 - 1

        rcv_next, snd_next, _, src_port = connection_passive_open(
            receive_window=advertised_window, dst_port=port_number
        )

        if rcv_next is None:
            ctx.__exit__(None, None, None)
            self.fail(
                "Failed to establish connection with sender in the "
                "handshake process"
            )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", port_number))
        sock.setblocking(False)

        # Give the sender time to start transmitting after the handshake,
        # matching the delay used in check_window_size.
        time.sleep(1)

        last_ack = None
        empty_rounds = 0
        # Receive and ACK packets to get data flowing.  Allow a few empty
        # rounds so we don't bail out if the first sniff is slightly early.
        for _ in range(20):
            pkts, _ = my_scapy.sniff(1, 0.5, sock=sock)
            if len(pkts) == 0:
                empty_rounds += 1
                if empty_rounds >= 3:
                    break
                continue
            empty_rounds = 0
            for pkt in pkts:
                pkt = get_utcs(pkt)
                if pkt is None:
                    continue
                if (pkt.flags & SYN_MASK) == SYN_MASK:
                    ack = pkt.seq_num + 1
                else:
                    ack = pkt.seq_num + len(pkt.payload)
                if last_ack is None or before(last_ack, ack):
                    last_ack = ack

            if last_ack is not None:
                ack_pkt = UTCSTCP(
                    plen=23,
                    source_port=port_number,
                    destination_port=src_port,
                    advertised_window=advertised_window,
                    seq_num=snd_next,
                    flags=ACK_MASK,
                    ack_num=last_ack,
                )
                sock.sendto(bytes(ack_pkt), ("127.0.0.1", src_port))

        if last_ack is None:
            sock.close()
            ctx.__exit__(None, None, None)
            self.fail("Did not receive any data packets from sender.")

        return port_number, sock, src_port, snd_next, last_ack, ctx

    def _send_zero_window_and_drain(
        self, sock, port_number, src_port, snd_next, last_ack
    ):
        """Send a window=0 ACK, then drain any stale in-flight packets from
        the socket, ACKing them with window=0 so the sender gets a fresh
        (non-duplicate) ACK.  Returns the updated last_ack."""
        # Initial window=0 ACK.
        ack_pkt = UTCSTCP(
            plen=23,
            source_port=port_number,
            destination_port=src_port,
            advertised_window=0,
            seq_num=snd_next,
            flags=ACK_MASK,
            ack_num=last_ack,
        )
        sock.sendto(bytes(ack_pkt), ("127.0.0.1", src_port))

        # Drain any data packets that were already in flight before the
        # sender processed our window=0.  ACK each one with window=0 so
        # the sender sees a *new* ACK (not a dup) carrying window=0.
        time.sleep(0.5)
        stale_pkts, _ = my_scapy.sniff(50, 1.0, sock=sock)
        for pkt in stale_pkts:
            pkt = get_utcs(pkt)
            if pkt is None:
                continue
            payload_len = pkt.plen - pkt.hlen
            if payload_len > 0:
                pkt_ack = pkt.seq_num + payload_len
                if before(last_ack, pkt_ack):
                    last_ack = pkt_ack
        # Send a final ACK covering everything we drained.
        ack_pkt = UTCSTCP(
            plen=23,
            source_port=port_number,
            destination_port=src_port,
            advertised_window=0,
            seq_num=snd_next,
            flags=ACK_MASK,
            ack_num=last_ack,
        )
        sock.sendto(bytes(ack_pkt), ("127.0.0.1", src_port))
        print(f"Advertising window = 0 (last_ack={last_ack})")
        return last_ack

    @partial_credit(10.0)
    @number("3.3")
    def test_zero_window_stops_sender(self, set_score: Callable[[float], None]) -> None:
        """Test that the sender stops transmitting data when the receiver
        advertises a window of zero."""
        print(
            "Flow control test - this test checks if the sender stops "
            "sending data when the advertised window is zero."
        )
        port_number, sock, src_port, snd_next, last_ack, ctx = \
            self._setup_zero_window_test()
        try:
            last_ack = self._send_zero_window_and_drain(
                sock, port_number, src_port, snd_next, last_ack
            )

            # Now collect any packets the sender transmits.  With window=0,
            # the sender should only send zero-window probes (1 byte each)
            # and must not send full-sized data segments.
            time.sleep(1)
            probe_pkts, _ = my_scapy.sniff(50, 3.0, sock=sock)
            sock.close()

            for pkt in probe_pkts:
                pkt = get_utcs(pkt)
                if pkt is None:
                    continue
                payload_len = pkt.plen - pkt.hlen
                if payload_len > 1:
                    self.fail(
                        f"Sender sent a packet with {payload_len} bytes of "
                        f"payload while advertised window was 0. Expected at "
                        f"most 1-byte zero-window probes."
                    )

            print(
                f"Sender correctly limited transmissions with zero window "
                f"({len(probe_pkts)} probe(s) received)."
            )
            set_score(10.0)
        finally:
            ctx.__exit__(None, None, None)
