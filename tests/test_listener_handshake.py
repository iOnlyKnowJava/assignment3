# Copyright (C) 2022 Carnegie Mellon University
# Copyright (C) 2025 University of Texas at Austin
#
# No part of the project may be copied and/or distributed without the express
# permission of the course staff.

import random
import subprocess
import time
import unittest
from contextlib import contextmanager

from gradescope_utils.autograder_utils.decorators import number, partial_credit, weight
from scapy.all import Raw

from test_support import my_scapy
from test_support.config import (
    ACK_MASK,
    UTCSTCP,
    DATA_ACK_MASK,
    DEFAULT_ISN,
    FIN_MASK,
    SNIFF_TIMEOUT,
    SYN_MASK,
    TIMEOUT,
    check_packet_is_valid_ack,
    check_packet_is_valid_synack,
    get_utcs,
    get_random_payload,
)
from test_support.constants import GRADER_SERVER
from test_support.open_conns import connection_active_open, get_free_port

handshake_no_response_packet_probes = {
    "packet without payload": UTCSTCP(plen=23, seq_num=0),
    "packet with payload": (
        UTCSTCP(plen=23 + len("probe!"), seq_num=0) / Raw(load="probe!")
    ),
    "packet with FIN": UTCSTCP(plen=23, seq_num=0, flags=FIN_MASK),
    "packet with ACK": UTCSTCP(plen=23, seq_num=0, flags=ACK_MASK),
}

handshake_response_packet_probes = {
    "initial seq num is 0": UTCSTCP(plen=23, seq_num=0, flags=SYN_MASK),
    "initial seq num is 1": UTCSTCP(plen=23, seq_num=1, flags=SYN_MASK),
    "initial seq num is 1000": UTCSTCP(plen=23, seq_num=1000, flags=SYN_MASK),
    "initial seq num is random": UTCSTCP(plen=23, seq_num=1000004, flags=SYN_MASK),
}

handshake_bad_ack_probes = {
    "syn ack flag": UTCSTCP(
        plen=23, seq_num=DEFAULT_ISN, ack_num=1, flags=SYN_MASK | ACK_MASK
    ),
    # Need to add isn we get during test to the ack numbers so they match what
    # we want for the test.
    "no flags": UTCSTCP(plen=23, seq_num=DEFAULT_ISN, ack_num=1, flags=0),
    # Should always reply to packets when sequence number is wrong with dup ack
    # (may need a different test for this).
    # 'sequence number is too small': ip/udp/CMUTCP(plen=23, seq_num=1,
    #                                               ack_num=1, flags=SYN_MASK),
    # We need to add 1, not 0 so too small.
    "too small ack num": UTCSTCP(
        plen=23, seq_num=DEFAULT_ISN, ack_num=0, flags=SYN_MASK
    ),
    # Mean test -- you should still do nothing.
    "too big ack num": UTCSTCP(
        plen=23, seq_num=DEFAULT_ISN, ack_num=12345, flags=SYN_MASK
    ),
}

payload_lengths = {
    "length 1": 1,
    "random length": random.randint(2, 1376),
    "another random length": random.randint(2, 1376),
    "length 750": 750,
    "length 1377": 1377,
}


@contextmanager
def launch_server(server_port: int):
    p = subprocess.Popen(
        [GRADER_SERVER, str(server_port)],
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

    @partial_credit(5.0)
    @number("2.1")
    def test_listener_waits(self, set_score):
        print(
            "Listener test - this test starts a TCP listener and sends "
            "invalid SYN packets."
        )
        test_score = 0

        for test_name, probe in handshake_no_response_packet_probes.items():
            print("-----------------------------------------")
            print(f"Testing invalid {test_name}.")
            server_port = get_free_port()
            client_port = get_free_port()
            with launch_server(server_port):
                resp = my_scapy.sr1(probe, TIMEOUT, True, server_port, client_port)
                if resp is None:
                    test_score += 1
                    print(f"Passed invalid {test_name}.")
                else:
                    print(
                        f"Failed invalid {test_name}. Listener responded to the"
                        " packet."
                    )

        set_score(test_score * 5 / 4)

    @partial_credit(5.0)
    @number("2.2")
    def test_syn_ack(self, set_score):
        print(
            "Listener test - this test starts a TCP listener and sends valid"
            " SYN packets."
        )
        test_score = 0

        for test_name, probe in handshake_response_packet_probes.items():
            print("-----------------------------------------")
            print(f"Testing {test_name}.")

            server_port = get_free_port()
            client_port = get_free_port()
            with launch_server(server_port):
                resp = my_scapy.sr1(probe, TIMEOUT, True, server_port, client_port)
                next_seq_num = probe[UTCSTCP].seq_num + 1
                if check_packet_is_valid_synack(get_utcs(resp), next_seq_num):
                    print(f"Passed {test_name}.")
                    test_score += 1
                else:
                    print(f"Failed {test_name}. Did not receive a valid SYN ACK")

        set_score(test_score * 5 / 4)

    @partial_credit(5.0)
    @number("2.3")
    def test_retransmit_syn_ack(self, set_score):
        print(
            "Listener test - this test starts a TCP listener and checks for "
            "retransmitted SYN ACK packets."
        )
        test_score = 0

        for test_name, probe in handshake_response_packet_probes.items():
            print("-----------------------------------------")
            print(f"Testing {test_name}.")
            server_port = get_free_port()
            client_port = get_free_port()
            with launch_server(server_port):
                my_scapy.sr1(probe, TIMEOUT, True, server_port, client_port)
                retrans, _ = my_scapy.sniff(0, SNIFF_TIMEOUT, client_port)

                if len(retrans) == 0:
                    print(
                        f"Failed {test_name}. Did not receive retransmitted SYN "
                        "ACK packet after 3 RTO."
                    )
                    continue

                all_correct = True

                for resp in retrans:
                    seq_num = probe[UTCSTCP].seq_num + 1
                    if not check_packet_is_valid_synack(get_utcs(resp), seq_num):
                        print(
                            f"Failed {test_name}. One of the retransmitted SYN "
                            f"ACK packets is not valid."
                        )
                        all_correct = False
                        break
                if all_correct:
                    print(f"Passed {test_name}.")
                    test_score += 1

        set_score(test_score * 5 / 4)

    @partial_credit(5.0)
    @number("2.4")
    def test_drops_bad_ack(self, set_score):
        print(
            "Listener test - this test starts a TCP listener and checks for "
            "invalid ACK packets after SYN ACK."
        )
        test_score = 0

        syn_pkt = UTCSTCP(plen=23, seq_num=DEFAULT_ISN, flags=SYN_MASK)

        for test_name, probe in handshake_bad_ack_probes.items():
            print("-----------------------------------------")
            print(f"Testing packet with {test_name}.")
            server_port = get_free_port()
            client_port = get_free_port()
            with launch_server(server_port):
                synack_pkt = my_scapy.sr1(
                    syn_pkt, TIMEOUT, True, server_port, client_port
                )
                if synack_pkt is None:
                    print("Failed - Did not receive SYN ACK packet from listener.")
                    continue

                utcs_pkt = get_utcs(synack_pkt)
                if utcs_pkt is None:
                    print("Failed - Issue parsing packet.")
                    continue

                isn = utcs_pkt.seq_num
                probe[UTCSTCP].ack_num = probe[UTCSTCP].ack_num + isn
                resp = my_scapy.sr1(probe, 1, True, server_port, client_port)
                if resp is not None:
                    if get_utcs(resp) != utcs_pkt:
                        print("Failed - Listener replies to the invalid ACK " "packet.")
                        continue

                test_score += 1
                print(f"Passed packet with {test_name}.")

        set_score(test_score * 5 / 4)

    @partial_credit(10.0)
    @number("2.5")
    def test_accept_data(self, set_score):
        print(
            "Listener test - this test starts a TCP listener and sends data "
            "packet to the listener."
        )
        test_score = 0.0

        for test_name, payload_len in payload_lengths.items():
            print("-----------------------------------------")
            print(f"Testing data packet with payload {test_name}")
            server_port = get_free_port()
            client_port = get_free_port()
            with launch_server(server_port):
                rcv_next, snd_next, _ = connection_active_open(
                    isn=DEFAULT_ISN, server_port=server_port, client_port=client_port
                )

                if rcv_next is None or snd_next is None:
                    print(f"Failed data packet with payload {test_name}.")
                    continue

                data = get_random_payload(payload_len)
                data_pkt = UTCSTCP(
                    plen=23 + len(data),
                    source_port=client_port,
                    destination_port=server_port,
                    seq_num=snd_next,
                    flags=0x0, # DATA_ACK_MASK,
                    ack_num=rcv_next,
                ) / Raw(load=data)

                resp = my_scapy.sr1(
                    data_pkt, SNIFF_TIMEOUT, True, server_port, client_port
                )
                if resp is None:
                    print(
                        f"Failed data packet with payload {test_name}. Did not "
                        "receive ACK packet after sending the data packet."
                    )
                    continue

                if check_packet_is_valid_ack(get_utcs(resp), snd_next + payload_len):
                    test_score += 2.0
                    print(f"Passed data packet with payload {test_name}.")
                else:
                    print(
                        f"Failed data packet with payload {test_name}. Packet "
                        "received is not a valid ACK."
                    )

        set_score(test_score)

    @weight(5.0)
    @number("2.6")
    def test_listener_random_sequence_number(self):
        print(
            "Listener test - this test checks if the listener initializes "
            "sequence numbers randomly."
        )

        syn_ack_pkts = []
        for test_name, probe in handshake_response_packet_probes.items():
            server_port = get_free_port()
            client_port = get_free_port()
            with launch_server(server_port):
                resp = my_scapy.sr1(probe, TIMEOUT, True, server_port, client_port)
                next_seq_num = probe[UTCSTCP].seq_num + 1
                if not check_packet_is_valid_synack(get_utcs(resp), next_seq_num):
                    self.fail(f"Failed {test_name}. Did not receive a valid SYN ACK")

                syn_ack_pkts.append(resp)

        seq_nums = set()
        for pkt in syn_ack_pkts:
            seq_nums.add(pkt[UTCSTCP].seq_num)

        if len(seq_nums) != len(handshake_response_packet_probes):
            self.fail(
                f"Sequence numbers are not sufficiently random. Got "
                f"{len(seq_nums)} unique sequence numbers out of "
                f"{len(handshake_response_packet_probes)} packets."
            )
