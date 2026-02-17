from collections import defaultdict
from sentinel.utils import current_time
from sentinel.detectors.base_detector import BaseDetector

class SSHBruteForceDetector(BaseDetector):
    def __init__(self, threshold, time_window, alert_callback):
        self.threshold = threshold
        self.time_window = time_window
        self.alert_callback = alert_callback
        self.attempts = defaultdict(list)

    def process(self, packet):
        if packet.haslayer("TCP") and packet.haslayer("IP"):
            if packet["TCP"].dport == 22:
                src = packet["IP"].src
                now = current_time()

                self.attempts[src] = [
                    ts for ts in self.attempts[src]
                    if now - ts <= self.time_window
                ]

                self.attempts[src].append(now)

                if len(self.attempts[src]) >= self.threshold:
                    self.alert_callback({
                        "type": "SSH_BRUTE_FORCE",
                        "source": src,
                        "attempts": len(self.attempts[src])
                    })
                    self.attempts[src].clear()
