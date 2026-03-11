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
    SNIFF_TIMEOUT,
    SYN_MASK,
    TIMEOUT,
    check_packet_is_valid_ack,
    get_utcs,
    get_random_payload,
)
from test_support.constants import GRADER_CLIENT
from test_support.open_conns import connection_passive_open, get_free_port

synack_packet_probes = {
    "inital seq num is 0": UTCSTCP(plen=23, seq_num=0, flags=SYN_MASK | ACK_MASK),
    "initial seq num is 1": UTCSTCP(plen=23, seq_num=1, flags=SYN_MASK | ACK_MASK),
    "initial seq num is 1000": UTCSTCP(plen=23, seq_num=1000, flags=SYN_MASK | ACK_MASK),
    "initial seq num is random0": UTCSTCP(
        plen=23, seq_num=random.randint(1, 10000), flags=SYN_MASK | ACK_MASK
    ),
    "initial seq num is random1": UTCSTCP(
        plen=23, seq_num=1000004, flags=SYN_MASK | ACK_MASK
    ),
}

synack_bad_packet_probes = {
    "only ack flag": UTCSTCP(plen=23, ack_num=1, seq_num=DEFAULT_ISN, flags=ACK_MASK),
    "no flags": UTCSTCP(plen=23, ack_num=1, seq_num=DEFAULT_ISN, flags=0),
    "ack num is too small": UTCSTCP(
        plen=23, ack_num=0, seq_num=DEFAULT_ISN, flags=SYN_MASK | ACK_MASK
    ),
    # mean test -- should still not respond
    "random incorrect ack number": UTCSTCP(
        plen=23,
        ack_num=random.randint(3, 12345),
        seq_num=DEFAULT_ISN,
        flags=SYN_MASK | ACK_MASK,
    ),
    "ack num is too big": UTCSTCP(
        plen=23, ack_num=12345, seq_num=DEFAULT_ISN, flags=SYN_MASK | ACK_MASK
    ),
}

payload_lengths = {
    "length 1": 1,
    "length 1000": 1000,
    "random length": random.randint(2, 1376),
    "length 1377": 1377,
}


@contextmanager
def launch_client(client_port: int) -> subprocess.Popen:
    p = subprocess.Popen(
        [GRADER_CLIENT, str(client_port)],
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

    @weight(5.0)
    @number("1.1")
    def test_initiator_syn(self):
        print(
            "Initiator test - this test starts a TCP initiator and checks "
            "for the first SYN packet."
        )

        port = get_free_port()
        with launch_client(port):
            syn_pkts, _ = my_scapy.sniff(count=0, timeout=SNIFF_TIMEOUT, portno=port)

            if len(syn_pkts) == 0:
                self.fail("Did not receive SYN packet from initiator after 3 RTO.")

            if syn_pkts[0][UTCSTCP].flags != SYN_MASK:
                self.fail(
                    f"First packet was not a syn packet. Expect only SYN flag in "
                    f"the first packet, but got {syn_pkts[0][UTCSTCP].flags}."
                )

    @partial_credit(5.0)
    @number("1.2")
    def test_initiator_ignores_bad_synack(self, set_score):
        print(
            "Initiator test - this test starts a TCP initiator and reply with "
            "bad SYN ACK."
        )

        test_score = 0.0

        for test_name, synack in synack_bad_packet_probes.items():
            print("-----------------------------------------")
            print(f"Testing {test_name}")

            port = get_free_port()
            with launch_client(port):
                syn_pkts, s_port = my_scapy.sniff(
                    count=1, timeout=SNIFF_TIMEOUT, portno=port
                )

                if len(syn_pkts) != 1 or syn_pkts[0][UTCSTCP].flags != SYN_MASK:
                    print(
                        f"Failed {test_name}. First packet sent by initiator was "
                        f"not a SYN packet."
                    )
                    continue

                syn_pkt = syn_pkts[0]
                syn_pkt = get_utcs(syn_pkt)
                if syn_pkt is None:
                    print(
                        f"Failed {test_name}. First packet sent by initiator was "
                        f"not a proper CMU-TCP packet."
                    )
                    continue

                isn = syn_pkt.seq_num
                dst_port = s_port

                synack[UTCSTCP].source_port = port
                synack[UTCSTCP].destination_port = dst_port
                synack[UTCSTCP].ack_num = synack[UTCSTCP].ack_num + isn
                resp = my_scapy.sr1(synack, TIMEOUT, False, dst_port, port)

                resp = get_utcs(resp)
                if resp is not None:
                    # Don't enforce equal sequence number.
                    resp.seq_num = syn_pkt.seq_num
                    if resp != syn_pkt:
                        print(
                            f"Failed {test_name}. Initiator responded to "
                            f"malformed SYN ACK."
                        )
                        continue
                test_score += 1.0
                print(f"Passed {test_name}")

        set_score(test_score)

    @partial_credit(10.0)
    @number("1.3")
    def test_initiator_accepts_data(self, set_score):
        print(
            "Initiator test - this test starts a TCP initiator and sends "
            "data to the initiator."
        )

        test_score = 0

        for test_name, payload_length in payload_lengths.items():
            print("-----------------------------------------")
            print(f"Testing data packet with {test_name}")
            port = get_free_port()
            with launch_client(port):
                rcv_next, snd_next, _, dst_port = connection_passive_open(
                    isn=302, dst_port=port
                )
                if rcv_next is None or snd_next is None:
                    print(
                        "Failed to establish connection with the initiator in "
                        "the handshake process"
                    )
                    continue

                data = get_random_payload(payload_length)
                data_pkt = UTCSTCP(
                    plen=23 + len(data),
                    seq_num=snd_next,
                    flags=0x0, # ACK_MASK,
                    ack_num=rcv_next,
                ) / Raw(load=data)

                data_pkt[UTCSTCP].destination_port = dst_port
                resp = my_scapy.sr1(data_pkt, SNIFF_TIMEOUT, False, dst_port, port)

                if resp is None:
                    print(
                        "Did not receive ACK packet from initiator after sending"
                        " the data packet."
                    )
                    continue

                if not check_packet_is_valid_ack(resp, snd_next + payload_length):
                    print("Received Invalid ACK packet.")
                    continue

                print(f"Passed data packet with {test_name}")
                test_score += 2.5

        set_score(test_score)

    @weight(5.0)
    @number("1.4")
    def test_initiator_random_sequence_number(self) -> None:
        print(
            "Initiator test - this test checks if the initiator initializes "
            "sequence numbers randomly."
        )

        nb_trials = 5

        syn_pkts = []
        for _ in range(nb_trials):
            port = get_free_port()
            with launch_client(port):
                pkts, _ = my_scapy.sniff(count=0, timeout=1, portno=port)

                if len(pkts) == 0:
                    self.fail(
                        "Did not receive SYN packet from initiator after 3 " "RTO."
                    )

                syn_pkt = pkts[0]

                if syn_pkt[UTCSTCP].flags != SYN_MASK:
                    self.fail(
                        f"First packet was not a syn packet. Expect only SYN flag "
                        f"in the first packet, but got {syn_pkt[UTCSTCP].flags}."
                    )

                syn_pkts.append(syn_pkt)

        seq_nums = set()
        for pkt in syn_pkts:
            seq_nums.add(pkt[UTCSTCP].seq_num)

        if len(seq_nums) != nb_trials:
            self.fail(
                "Sequence numbers are not sufficiently random. Got "
                f"{len(seq_nums)} unique sequence numbers out of "
                f"{nb_trials}."
            )
