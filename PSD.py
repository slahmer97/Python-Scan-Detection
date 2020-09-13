from abc import abstractmethod

from scapy.layers.inet import IP
from scapy.layers.inet import TCP

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


class ScanDetector:
    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def check(self, ether_packet):
        pass


class SynAckScanDetector(ScanDetector):
    def __init__(self):
        super().__init__()
        self.sus = {}
        self.counter = 0

    def check(self, ether_frame):
        self.counter += 1
        if self.counter == 14:
            print("here")
        if ether_frame.haslayer(IP) and ether_frame.haslayer(TCP):
            ip_packet = ether_frame[IP]
            tcp_segment = ether_frame[TCP]
            if ip_packet.src not in self.sus:
                self.sus[ip_packet.src] = {"SYN": 0, "SYN-ACK": 0, "MEAN": 0.0}
            flags = tcp_segment.flags
            print(list(flags))
            if 'A' in flags and 'S' in flags:
                self.sus[ip_packet.src]["SYN-ACK"] += 1
            elif 'A' not in flags and 'S' in flags:
                print("found it")
                self.sus[ip_packet.src]["SYN"] += 1

    def summary(self):
        for key in self.sus:
            if self.sus[key]["SYN"] > self.sus[key]["SYN-ACK"] * 3:
                print("{} -> {}".format(key, self.sus[key]))


from scapy.all import *
from scapy.layers.inet import TCP

rr = SynAckScanDetector()
data = "res.pcap"
print("reading file..")
a = rdpcap(data)
for p in a:
    rr.check(p)

rr.summary()
