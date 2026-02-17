from scapy.all import sniff

class PacketCapture:
    def __init__(self, interface, detectors):
        self.interface = interface
        self.detectors = detectors

    def start(self):
        sniff(
            iface=self.interface,
            prn=self.process_packet,
            store=False
        )

    def process_packet(self, packet):
        for detector in self.detectors:
            detector.process(packet)
