# ---------------------------------------------------#
#   open_conns.py                                   #
#                                                   #
#   Performs TCP establishment handshakes           #
#                                                   #
#   Kartik Chitturi <kartik.chitturi@gmail.com>     #
# ---------------------------------------------------#

import time

from scapy.all import *

from test_support import my_scapy
from test_support.config import (
    ACK_MASK,
    UTCSTCP,
    DEFAULT_ISN,
    MAX_ADV_WINDOW,
    SNIFF_TIMEOUT,
    SYN_MASK,
    TIMEOUT,
    check_packet_is_valid_ack,
    check_packet_is_valid_synack,
    get_utcs,
)


# Opens connection (incl. handshake) with TCP_LISTENER
# Args:
#   commListener: redundant
#   isn: initial sequence number
# Returns:
#   rcv_next: next seq number to receive
#   snd_next: next seq number to send
#   adv_window: listener's advertised window
#   (All three are None if error occurs)
def connection_active_open(isn=DEFAULT_ISN, server_port=12000, client_port=11111):
    rcv_next = 0
    snd_next = 0
    adv_window = 65535

    syn_pkt = UTCSTCP(plen=23, seq_num=isn, flags=SYN_MASK)
    synack_pkt = my_scapy.sr1(syn_pkt, TIMEOUT, True, server_port, client_port)
    if synack_pkt is None:
        msg = (
            "Incorrect handshake implementation. Did not get a SYN+ACK "
            "reply to SYN packet."
        )
        print(msg)
        return None, None, None

    check_packet_is_valid_synack(synack_pkt, isn + 1)
    isn = get_utcs(synack_pkt).seq_num
    rcv_next = isn + 1
    seq_num = (syn_pkt.seq_num) + 1
    snd_next = seq_num
    adv_window = get_utcs(synack_pkt).advertised_window
    ack_pkt = UTCSTCP(plen=23, seq_num=seq_num, ack_num=rcv_next, flags=ACK_MASK)
    resp = my_scapy.sr1(ack_pkt, TIMEOUT, True, server_port, client_port)
    if resp is not None:
        msg = "Incorrect handshake implementation."
        msg += " Got an unexpected response"
        msg += " to a valid final ACK during handshake."
        print(msg)
        return None, None, None
    return rcv_next, snd_next, adv_window


# Opens connection (incl. handshake) with TCP_INITIATOR
# Args:
#   isn: initial sequence number
#   receive_window: advertised window to send in SYN+ACK
#   expected_advertised_window: advertised window that should be sent
# Returns:
#   rcv_next: next seq number to receive
#   snd_next: next seq number to send
#   adv_window: listener's advertised window
#   dst_port: port numberof TCP_INITIATOR
#   (All four are None if error occurs)
def connection_passive_open(
    isn=DEFAULT_ISN,
    receive_window=65535,
    expected_advertised_window=MAX_ADV_WINDOW,
    dst_port=12000,
    delay=None,
):
    rcv_next = 0
    snd_next = 0
    adv_window = expected_advertised_window
    bind_port = dst_port

    syn_pkts, s_port = my_scapy.sniff(count=1, timeout=SNIFF_TIMEOUT, portno=bind_port)
    if len(syn_pkts) < 1:
        msg = "Incorrect handshake implementation."
        msg += " Initiator did not send SYN packet after 3 RTO"
        print(msg)
        return None, None, None, None

    if delay is not None:
        time.sleep(delay)

    syn_pkt = syn_pkts[0]
    other_side_isn = get_utcs(syn_pkt).seq_num

    synack_pkt = UTCSTCP(
        plen=23,
        seq_num=isn,
        ack_num=other_side_isn + 1,
        advertised_window=receive_window,
        source_port=bind_port,
        destination_port=s_port,
        flags=SYN_MASK | ACK_MASK,
    )

    dst_port = s_port
    synack_pkt[UTCSTCP].destination_port = dst_port
    ack_pkt = my_scapy.sr1(synack_pkt, TIMEOUT, False, dst_port, bind_port)

    if ack_pkt is None:
        msg = "Incorrect handshake implementation. "
        msg += "Initiator did not send ACK in response to SYN+ACK"
        print(msg)
        return None, None, None, None

    if not check_packet_is_valid_ack(ack_pkt, synack_pkt[UTCSTCP].seq_num + 1):
        msg = "Incorrect handshake implementation. "
        msg += "Initiator did not send valid ACK to SYN+ACK"
        print(msg)
        return None, None, None, None

    ack_utcs = get_utcs(ack_pkt)
    if (
        ack_utcs.plen != ack_utcs.hlen
        or len(ack_utcs) != ack_utcs.hlen
        or len(ack_utcs.payload) != 0
    ):
        msg = "Incorrect handshake implementation. "
        msg += "Response to SYN+ACK has ACK flag and correct ACK num, "
        msg += "But there is an unexpected plen/payload"
        print(msg)
        return None, None, None, None

    adv_window = ack_utcs.advertised_window
    snd_next = synack_pkt[UTCSTCP].seq_num + 1
    rcv_next = other_side_isn + 1

    if snd_next != isn + 1:
        print("Unexpected error: Please contact TA")
        return None, None, None, None

    return rcv_next, snd_next, adv_window, dst_port


def get_free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    portno = sock.getsockname()[1]
    sock.close()
    return portno
