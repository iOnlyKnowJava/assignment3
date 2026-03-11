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

from gradescope_utils.autograder_utils.decorators import number, partial_credit
from scapy.all import Raw

from test_support import my_scapy
from test_support.config import (
    ACK_MASK,
    UTCSTCP,
    DEFAULT_ISN,
    SNIFF_TIMEOUT,
    SYN_MASK,
    check_for_crash_and_kill,
    check_packet_is_valid_inorder_data,
    get_random_payload,
    get_utcs,
)
from test_support.constants import GRADER_SENDER, GRADER_WAITER
from test_support.open_conns import (
    connection_active_open,
    connection_passive_open,
    get_free_port,
)


def before(s1, s2):
    return (s1 - s2) & 0xFFFFFFFF > 0x7FFFFFFF


@contextmanager
def launch_grader(app_path, portno):
    p = subprocess.Popen(
        [app_path, str(portno)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(1)
        yield p
    finally:
        p.terminate()
        p.wait()


class TestCases(unittest.TestCase):
    def setUp(self):
        self.startTime = time.time()

    def tearDown(self):
        t = time.time() - self.startTime
        print("Duration of %s: %.3fs" % (self.id(), t))

    @partial_credit(10.0)
    @number("4.1")
    def test_retransmit_data(self, set_score):
        print(
            "Retransmission test - this test checks if sender retransmits "
            "data packets on timeout."
        )

        rcv_wndw = 2**16 - 1
        portno = get_free_port()

        p = subprocess.Popen(
            [GRADER_SENDER, str(portno)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        rcv_next, snd_next, _, _ = connection_passive_open(
            False, receive_window=rcv_wndw, dst_port=portno
        )

        if rcv_next is None:
            check_for_crash_and_kill(p)
            set_score(0.0)
            self.fail(
                "Failed to establish connection with sender in the " "handshake process"
            )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", portno))
        sock.settimeout(3)

        try:
            data, _ = sock.recvfrom(4096)
        except Exception:
            data = None

        if data is None or (data_pkt := get_utcs(UTCSTCP(data))) is None:
            check_for_crash_and_kill(p)
            print("Did not receive data packet from the sender.")
            set_score(0.0)
            return

        if not check_packet_is_valid_inorder_data(data_pkt, rcv_next, snd_next):
            check_for_crash_and_kill(p)
            print(
                "Got a packet but the sequence number is different from what"
                f" was expected."
            )
            set_score(0.0)
            return

        retrans_data_pkts, _ = my_scapy.sniff(100, SNIFF_TIMEOUT, sock=sock)

        if len(retrans_data_pkts) == 0:
            check_for_crash_and_kill(p)
            print("Did not receive retransmitted data packet from the sender.")
            set_score(0.0)
            return

        for retrans_pkt in retrans_data_pkts:
            if retrans_pkt[UTCSTCP].seq_num == data_pkt[UTCSTCP].seq_num:
                check_for_crash_and_kill(p)
                print("Passed data packet retransmission test.")
                set_score(10.0)
                return

        check_for_crash_and_kill(p)
        print("Did not receive retransmitted data packet from the sender.")
        set_score(0.0)

    @partial_credit(10.0)
    @number("4.2")
    def test_gap_filling_ack(self, set_score):
        """Test that the receiver ACKs the highest contiguous sequence number
        after a gap is filled by a late-arriving packet."""
        print(
            "Gap filling test - this test sends packets out of order to the "
            "receiver, then sends the missing packet and checks that the "
            "receiver ACKs the highest contiguous sequence number."
        )

        server_port = get_free_port()
        client_port = get_free_port()

        with launch_grader(GRADER_WAITER, server_port):
            rcv_next, snd_next, _ = connection_active_open(
                isn=DEFAULT_ISN, server_port=server_port, client_port=client_port
            )

            if rcv_next is None or snd_next is None:
                set_score(0.0)
                self.fail(
                    "Failed to establish connection with receiver in the "
                    "handshake process"
                )

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", client_port))
            sock.settimeout(float(SNIFF_TIMEOUT))

            payload_size = 100
            # We will send 3 packets: pkt0, pkt1, pkt2
            # Sequence numbers: pkt0 starts at snd_next,
            #                   pkt1 starts at snd_next + payload_size,
            #                   pkt2 starts at snd_next + 2 * payload_size

            seq0 = snd_next
            seq1 = snd_next + payload_size
            seq2 = snd_next + 2 * payload_size

            def make_data_pkt(seq_num):
                data = get_random_payload(payload_size)
                packet_len = len(data) + 23
                return UTCSTCP(
                    plen=packet_len,
                    seq_num=seq_num,
                    flags=ACK_MASK,
                    ack_num=rcv_next,
                    source_port=client_port,
                    destination_port=server_port,
                ) / Raw(load=data)

            # Step 1: Send pkt0 (in order) and get ACK
            pkt0 = make_data_pkt(seq0)
            sock.sendto(bytes(pkt0), ("127.0.0.1", server_port))

            try:
                data, _ = sock.recvfrom(4096)
            except Exception:
                data = None

            if data is None:
                set_score(0.0)
                self.fail("Did not receive ACK for first data packet.")

            ack_pkt = get_utcs(UTCSTCP(data))
            if ack_pkt is None or ack_pkt.ack_num != seq0 + payload_size:
                set_score(0.0)
                self.fail(
                    f"Expected ACK number {seq0 + payload_size} for first "
                    f"packet, got {ack_pkt.ack_num if ack_pkt else 'None'}."
                )

            print(f"Received correct ACK {ack_pkt.ack_num} for first packet.")

            # Step 2: Skip pkt1, send pkt2 (out of order)
            pkt2 = make_data_pkt(seq2)
            sock.sendto(bytes(pkt2), ("127.0.0.1", server_port))

            try:
                data, _ = sock.recvfrom(4096)
            except Exception:
                data = None

            if data is None:
                set_score(0.0)
                self.fail(
                    "Did not receive ACK after sending out-of-order packet."
                )

            ack_pkt_oo = get_utcs(UTCSTCP(data))
            if ack_pkt_oo is None:
                set_score(0.0)
                self.fail("Received invalid packet after out-of-order send.")

            # The receiver should still ACK the last contiguous byte
            # (i.e., seq0 + payload_size), since pkt1 is missing.
            if ack_pkt_oo.ack_num != seq0 + payload_size:
                print(
                    f"After out-of-order packet, receiver ACKed "
                    f"{ack_pkt_oo.ack_num} instead of expected "
                    f"{seq0 + payload_size}. This is acceptable as long as "
                    f"the final gap-fill ACK is correct."
                )

            print(
                f"Received ACK {ack_pkt_oo.ack_num} after out-of-order "
                f"packet (pkt1 skipped)."
            )

            # Step 3: Now send the missing pkt1 (fill the gap)
            pkt1 = make_data_pkt(seq1)
            sock.sendto(bytes(pkt1), ("127.0.0.1", server_port))

            # Collect ACKs - the receiver should now ACK up to seq2 + payload_size
            expected_ack = seq2 + payload_size
            found_correct_ack = False

            ack_pkts, _ = my_scapy.sniff(10, SNIFF_TIMEOUT, sock=sock)

            for pkt in ack_pkts:
                ack = get_utcs(pkt)
                if ack is not None and ack.ack_num == expected_ack:
                    found_correct_ack = True
                    break

            if found_correct_ack:
                print(
                    f"Passed gap filling test. Receiver correctly ACKed "
                    f"{expected_ack} (highest contiguous sequence number) "
                    f"after the missing packet arrived."
                )
                set_score(10.0)
            else:
                ack_nums = [
                    get_utcs(p).ack_num
                    for p in ack_pkts
                    if get_utcs(p) is not None
                ]
                print(
                    f"Failed gap filling test. Expected receiver to ACK "
                    f"{expected_ack} after gap was filled, but received "
                    f"ACKs: {ack_nums}"
                )
                set_score(0.0)
                assert False
