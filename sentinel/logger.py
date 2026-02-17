import logging
import json

def setup_logger(log_file, level):
    logger = logging.getLogger("SentinelIDS")
    logger.setLevel(level)

    handler = logging.FileHandler(log_file)
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    return logger

def log_alert(logger, alert_data):
    logger.warning(json.dumps(alert_data))
