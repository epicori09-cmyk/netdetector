# config - change these!
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""
# detection thresholds
SYN_FLOOD_THRESHOLD = 0.8  # syn / total tcp
PORT_SCAN_THRESHOLD = 10   # unique dst ports
HIGH_TRAFFIC_THRESHOLD = 100  # packets per second
ANOMALY_SCORE_THRESHOLD = -0.3  # isolation forest threshold