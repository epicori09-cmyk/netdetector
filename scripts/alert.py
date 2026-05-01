# send alerts via telegram
import requests
import config

def send_alert(message):
    print(f"[ALERT] {message}")
    if not config.TELEGRAM_BOT_TOKEN:
        print("  (no telegram token set, skipping)")
        return False
    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": config.TELEGRAM_CHAT_ID,
        "text": f"[NETDETECT] {message}",
    }
    try:
        r = requests.post(url, data=data, timeout=10)
        if r.status_code == 200:  
            print("  sent to telegram")
            return True
        else:
            print(f"  telegram error: {r.text}")
            return False
    except Exception as e:
        print(f"  telegram failed: {e}")
        return False

def alert_anomaly(detection_type, details):
    msg = f"{detection_type}: {details}"
    send_alert(msg)