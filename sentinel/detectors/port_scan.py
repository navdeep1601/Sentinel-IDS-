from collections import defaultdict
from sentinel.utils import current_time
from sentinel.detectors.base_detector import BaseDetector

class PortScanDetector(BaseDetector):
    def __init__(self, threshold, time_window, alert_callback):
        self.threshold = threshold
        self.time_window = time_window
        self.alert_callback = alert_callback
        self.tracker = defaultdict(list)

    def process(self, packet):
        if packet.haslayer("TCP") and packet.haslayer("IP"):
            src = packet["IP"].src
            dst_port = packet["TCP"].dport
            now = current_time()

            self.tracker[src] = [
                (port, ts) for port, ts in self.tracker[src]
                if now - ts <= self.time_window
            ]

            self.tracker[src].append((dst_port, now))
            unique_ports = len(set(p for p, _ in self.tracker[src]))

            if unique_ports >= self.threshold:
                self.alert_callback({
                    "type": "PORT_SCAN",
                    "source": src,
                    "unique_ports": unique_ports
                })
                self.tracker[src].clear()
