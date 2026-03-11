from config import *
from scapy.all import *


def save_pkts(file_prefix):
    in_file = open(file_prefix + ".pkts", "rb")
    pcap_file = file_prefix + ".pcap"
    while True:
        b_len = in_file.read(2)
        if b_len == b"":
            break
        pkt_len = int.from_bytes(b_len, "little")
        curr_packet = in_file.read(pkt_len)
        utcs_pkt = get_utcs(curr_packet)
        if utcs_pkt is not None:
            wrpcap(pcap_file, utcs_pkt, append=True)


def create_pcaps():
    save_pkts("grader_reliable_lossless")
    save_pkts("grader_reliable_lossy")


if __name__ == "__main__":
    pass
