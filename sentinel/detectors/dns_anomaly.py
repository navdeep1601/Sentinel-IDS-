from collections import defaultdict
from sentinel.utils import current_time
from sentinel.detectors.base_detector import BaseDetector

class DNSAnomalyDetector(BaseDetector):
    def __init__(self, threshold, time_window, alert_callback):
        self.threshold = threshold
        self.time_window = time_window
        self.alert_callback = alert_callback
        self.requests = defaultdict(list)

    def process(self, packet):
        if packet.haslayer("UDP") and packet.haslayer("IP"):
            if packet["UDP"].dport == 53:
                src = packet["IP"].src
                now = current_time()

                self.requests[src] = [
                    ts for ts in self.requests[src]
                    if now - ts <= self.time_window
                ]

                self.requests[src].append(now)

                if len(self.requests[src]) >= self.threshold:
                    self.alert_callback({
                        "type": "DNS_ANOMALY",
                        "source": src,
                        "requests": len(self.requests[src])
                    })
                    self.requests[src].clear()
