import argparse
import yaml
from sentinel.packet_capture import PacketCapture
from sentinel.detectors.port_scan import PortScanDetector
from sentinel.detectors.ssh_bruteforce import SSHBruteForceDetector
from sentinel.detectors.syn_flood import SYNFloodDetector
from sentinel.detectors.dns_anomaly import DNSAnomalyDetector
from sentinel.alert_manager import AlertManager
from sentinel.logger import setup_logger

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

def main():
    parser = argparse.ArgumentParser(description="SentinelIDS - Intelligent Network Threat Detection")
    parser.add_argument("-i", "--interface", required=True, help="Network interface (e.g., eth0)")
    args = parser.parse_args()

    config = load_config()
    logger = setup_logger(config["logging"]["file"], config["logging"]["level"])
    alert_manager = AlertManager(logger)

    detectors = [
        PortScanDetector(
            config["thresholds"]["port_scan"]["unique_ports"],
            config["thresholds"]["port_scan"]["time_window"],
            alert_manager.alert
        ),
        SSHBruteForceDetector(
            config["thresholds"]["ssh_bruteforce"]["attempts"],
            config["thresholds"]["ssh_bruteforce"]["time_window"],
            alert_manager.alert
        ),
        SYNFloodDetector(
            config["thresholds"]["syn_flood"]["syn_threshold"],
            config["thresholds"]["syn_flood"]["time_window"],
            alert_manager.alert
        ),
        DNSAnomalyDetector(
            config["thresholds"]["dns_anomaly"]["request_threshold"],
            config["thresholds"]["dns_anomaly"]["time_window"],
            alert_manager.alert
        ),
    ]

    capture = PacketCapture(args.interface, detectors)
    print(f"[+] Monitoring interface: {args.interface}")
    capture.start()

if __name__ == "__main__":
    main()
