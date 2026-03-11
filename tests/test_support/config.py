# -------------------------------------------------------#
#   config.py                                           #
#                                                       #
#   Basic variables and functions used by framework     #
#                                                       #
#   Kartik Chitturi <kartik.chitturi@gmail.com>         #
# -------------------------------------------------------#

import random
import string

from scapy.all import (
    ByteEnumField,
    IntField,
    L3RawSocket,
    Packet,
    Raw,
    ShortField,
    StrLenField,
    conf,
)
from scapy.layers.inet import ICMP, IP, UDP

# --------------------------#
# Define network variables #
# --------------------------#

conf.L3socket = L3RawSocket

IFNAME = "lo"

HOSTNAME = "server"
TESTING_HOSTNAME = "client"


IP_ADDRS = {"client": "127.0.0.1", "server": "127.0.0.1"}

HOST_IP = IP_ADDRS[HOSTNAME]
HOST_MAC = "ff:ff:ff:ff:ff:ff"
HOST_PORT = 12000
TESTING_HOST_IP = IP_ADDRS[TESTING_HOSTNAME]
TESTING_HOST_MAC = "00:00:00:00:00:00"
TESTING_HOST_PORT = 11111

ip = IP()
udp = UDP(sport=11111, dport=12000)


# Define CMU-TCP variables.
FIN_MASK = 0x2
ACK_MASK = 0x4
SYN_MASK = 0x8

DATA_ACK_MASK = ACK_MASK

RESPONDS_TO_ACKS_MASK = 0xF

TIMEOUT = 1
SNIFF_TIMEOUT = TIMEOUT * 3
DEFAULT_RTT = 0.04  # in seconds
DEFAULT_ISN = 0
MAX_ADV_WINDOW = 65535
MSS = 1377


class UTCSTCP(Packet):
    name = "UTCS TCP"
    fields_desc = [
        IntField("identifier", 53310),
        ShortField("source_port", TESTING_HOST_PORT),
        ShortField("destination_port", HOST_PORT),
        IntField("seq_num", 0),
        IntField("ack_num", 0),
        ShortField("hlen", 23),
        ShortField("plen", 23),
        ByteEnumField(
            "flags",
            DATA_ACK_MASK,
            {
                FIN_MASK: "FIN",
                ACK_MASK: "ACK",
                SYN_MASK: "SYN",
                FIN_MASK | ACK_MASK: "FIN ACK",
                SYN_MASK | ACK_MASK: "SYN ACK",
            },
        ),
        ShortField("advertised_window", MAX_ADV_WINDOW),
    ]

    def answers(self, other):
        if not isinstance(other, UTCSTCP):
            return False
        if ICMP in other:
            return False
        if ICMP in self:
            return False
        return True


def get_utcs(pkt):
    """Converts a raw packet into a UTCS TCP packet.

    (For some reason, scapy doesn't always do this automatically.)

    Args:
        pkt (scapy.packet.Packet): The packet to convert.
    """
    if pkt is None:
        return None
    elif UTCSTCP in pkt:
        return pkt[UTCSTCP]
    elif Raw in pkt:
        try:
            return UTCSTCP(pkt[Raw])
        except Exception:
            return None
    else:
        return None


def get_random_payload(length=None):
    if length is None:
        length = random.randint(1, MSS)
    if length <= 0:
        return ""
    return "".join(
        random.choice(
            string.ascii_uppercase + string.digits + " " + string.ascii_lowercase
        )
        for _ in range(length)
    )


def check_packet_is_valid_synack(pkt, expected_ack_num):
    """Check packets for required characteristics."""
    if pkt is None:
        print("Did not receive SYN+ACK packet")
        return False
    pkt = get_utcs(pkt)
    if pkt is None:
        print("Received packet is not a CMUTCP packet")
        return False
    if not (pkt.flags & SYN_MASK):
        print("SYN+ACK packet does not contain SYN flag")
        return False
    if pkt.flags != (SYN_MASK | ACK_MASK):
        print("SYN+ACK packet has SYN flag but no ACK flag")
        return False
    if pkt.ack_num != expected_ack_num:
        print("SYNACK packet's ACK number is incorrect")
        return False
    if pkt.plen != pkt.hlen or len(pkt) != pkt.hlen or len(pkt.payload) != 0:
        print("SYNACK packet has unexpected plen/payload")
        return False
    return True


def check_packet_is_valid_ack(pkt, expected_ack_num, expected_seq_num=None):
    if pkt is None:
        print("Did not receive ACK packet")
        return False
    pkt = get_utcs(pkt)
    if pkt is None:
        print("Received packet is not a CMUTCP packet")
        return False
    if pkt.flags != ACK_MASK:
        print("ACK packet does not contain ACK flag")
        return False
    if pkt.ack_num != expected_ack_num:
        print(
            f"ACK packet has incorrect ACK number. Expected ACK number "
            f"{expected_ack_num}. Got ACK number {pkt.ack_num}"
        )
        return False
    if expected_seq_num is not None:
        if pkt.seq_num != expected_seq_num:
            print(
                f"ACK packet has incorrect SEQ number. Expected SEQ number "
                f"{expected_seq_num}. Got SEQ number {pkt.seq_num}"
            )
            return False
    return True


def check_packet_is_valid_inorder_data(pkt, expected_seq_num, expected_ack_num):
    if pkt is None:
        print("Sender did not send data.")
        return False
    pkt = get_utcs(pkt)
    if pkt is None:
        print("Sender sent invalid data.")
        return False
    if pkt.seq_num != expected_seq_num:
        print("Sender sent data with an incorrect sequence number.")
        return False
    # if pkt.flags != ACK_MASK:
    #     print("Sender sent data without an ACK flag.")
    #     return False
    if pkt.ack_num != expected_ack_num:
        print(
            f"Sender sent data with incorrect ACK number. Expected ACK "
            f"number {expected_ack_num}. Got ACK number {pkt.ack_num}."
        )
        return False
    dlen = pkt.plen - pkt.hlen
    if dlen != len(pkt.payload):
        print(
            f"Sender sent data with a payload length not equal to plen-hlen. "
            f"Actual payload length {len(pkt.payload)}. plen-hlen from packet "
            f"header {dlen}."
        )
        return False
    return True


def check_for_crash_and_kill(process):
    if process.poll() is None:
        process.kill()
        return

    print(
        "The test program was not running when the autograder tried to "
        "terminate it. Your implementation may have crashed."
    )
