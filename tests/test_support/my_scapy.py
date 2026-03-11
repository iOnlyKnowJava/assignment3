# my_scapy.py
#
# My version of Python's scapy package which does not require the ability to
# open raw sockets.
#
# Kartik Chitturi <kartik.chitturi@gmail.com>

import socket
import time

from test_support.config import UTCSTCP, get_utcs

T_UDP_IP = "127.0.0.1"
T_UDP_PORT = 12000

test_addr = (T_UDP_IP, T_UDP_PORT)


# Send a packet and receive at most one back
# Args:
#   message: packet to send
#   timeout: socket timeout arg
#   commListener: True iff communicating with TCP_LISTENER
#   dest_port: Port to send message to (only used if commListener==False)
# Returns:
#   packet if one was received, else None
def sr1(message, timeout, commListener, dest_port, bind_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", bind_port))
    if commListener:
        if dest_port is None:
            sock.sendto(bytes(message), test_addr)
        else:
            sock.sendto(bytes(message), ("127.0.0.1", dest_port))
    else:
        sock.sendto(bytes(message), ("127.0.0.1", dest_port))
    sock.settimeout(timeout)
    try:
        data, rcv_addr = sock.recvfrom(4096)
        data = get_utcs(UTCSTCP(data))
    except Exception:
        data = None
    finally:
        sock.close()
    return data


# Send a packet
# Args:
#   message: packet to send
#   commListener: True iff communicating with TCP_LISTENER
#   dest_port: Port to send message to (only used if commListener==False)
# Returns:
#   Nothing
def send(message, bind_port, dest_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", bind_port))
    sock.sendto(bytes(message), ("127.0.0.1", dest_port))


# TODO: Could definitely make timing out better
# Sniff packets on iface
# Args:
#   count: max number of packets to sniff for (0 means no limit)
#   timeout: socket timeout arg
#   commListener: True iff communicating with TCP_LISTENER
# Returns:
#   List of packets (possibly empty)
def sniff(count, timeout, portno=12000, sock=None):
    if count == 0:
        count = float("inf")

    close_on_exit = False
    if sock is None:
        close_on_exit = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", portno))
        sock.settimeout(float(timeout) / 10.0)

    pkts = []
    num_pkts = 0
    start_time = time.time()
    end_time = start_time
    rcv_addr = ("0.0.0.0", -1)
    while (end_time - start_time) < timeout:
        try:
            data, rcv_addr = sock.recvfrom(4096)
        except Exception:
            data = None
        if data is not None:
            pkts.append(UTCSTCP(data))
            num_pkts += 1
            if num_pkts == count:
                break
        end_time = time.time()

    if close_on_exit:
        sock.close()
    return pkts, rcv_addr[1]
