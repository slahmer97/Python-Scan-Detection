from abc import abstractmethod

from scapy.layers.inet import IP, ICMP, UDP
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


class UdpScanDetector(ScanDetector):
    def __init__(self):
        super().__init__()
        self.counter = 0
        self.udp_his = {}

    def check(self, ether_frame):
        self.counter += 1
        if UDP not in ether_frame:
            return
        if ether_frame[UDP].len == 8:
            if ether_frame[IP].src not in self.udp_his:
                self.udp_his[ether_frame[IP].src] = {"target": set(), "count": 0}
            self.udp_his[ether_frame[IP].src]["count"] += 1
            self.udp_his[ether_frame[IP].src]["target"].add(
                {
                    "ip": ether_frame[IP].src,
                    "port": ether_frame[UDP].dport
                }
            )

    def summary(self):
        print("Udp Scan :")
        print("{} Packets were analyser for UDP scan attemps".format(self.counter))
        for key in self.udp_his:
            print("{} -> target : {}".format(key, self.udp_his[key]["target"]))


class IcmpScanDetector(ScanDetector):
    def __init__(self):
        super().__init__()
        self.icmp = {}
        self.counter = 0

    def check(self, ether_frame):
        self.counter += 1
        if ICMP in ether_frame:
            if ether_frame[ICMP].type == 8:
                if ether_frame[IP].src not in self.icmp:
                    self.icmp[ether_frame[IP].src] = {"count": 0, "target": set()}
                self.icmp[ether_frame[IP].src]["count"] += 1
                self.icmp[ether_frame[IP].src]["target"].add(ether_frame[IP].dst)

    def summary(self):
        print("ICMP Scan :")
        print("{} Packets were analyser for ICMP scan attemps".format(self.counter))
        for z in self.icmp:
            print("{} ({} times)-> {}".format(z, self.icmp[z]["count"], self.icmp[z]["target"]))


class SynAckScanDetector(ScanDetector):
    def __init__(self):
        super().__init__()
        self.sus = {}
        self.counter = 0

    def check(self, ether_frame):
        self.counter += 1
        if ether_frame.haslayer(IP) and ether_frame.haslayer(TCP):
            ip_packet = ether_frame[IP]
            tcp_segment = ether_frame[TCP]
            if ip_packet.src not in self.sus:
                self.sus[ip_packet.src] = {"SYN": 0, "SYN-ACK": 0, "MEAN": 0.0}
            flags = tcp_segment.flags
            if 'A' in flags and 'S' in flags:
                self.sus[ip_packet.src]["SYN-ACK"] += 1
            elif 'A' not in flags and 'S' in flags:
                # print("found it")
                self.sus[ip_packet.src]["SYN"] += 1

    def summary(self):
        print("Syn-Ack Scan :")
        print("{} Packets were analyser for Syn-Ack scan attemps".format(self.counter))
        for key in self.sus:
            if self.sus[key]["SYN"] > self.sus[key]["SYN-ACK"] * 3:
                print("{} -> {}".format(key, self.sus[key]))


from scapy.all import *
from scapy.layers.inet import TCP

scanners = [SynAckScanDetector(), IcmpScanDetector(), UdpScanDetector()]
data = "03.pcap"
print("reading file..")
a = rdpcap(data)
for p in a:
    for scanner in scanners:
        scanner.check(p)

for scanner in scanners:
    scanner.summary()
    print("============================================")
