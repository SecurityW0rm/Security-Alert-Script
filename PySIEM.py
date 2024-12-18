import smtplib
from email.mime.text import MIMEText
import win32evtlog
import win32evtlogutil
import win32con
import time
from collections import defaultdict

# ======================================================================EDIT BELOW HERE=============================================================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "your_email@gmail.com" #enter your email address
EMAIL_PASSWORD = "your_app_password" #enter the generated App Password
TO_EMAIL = "your_email@gmail.com" #enter your email again
#OPTIONAL: TEXT_EMAIL = "your_phone_number@carrier_gateway.com"  # Uncomment and replace with your carrier's email-to-text gateway
# ======================================================================EDIT BELOW HERE=============================================================

# Failed Password thresholds
FAILED_LOGIN_THRESHOLD = 5
EMAIL_LOGIN_THRESHOLD = 3
FAILED_LOGIN_RESET_TIME = 60  # Resets count after 60 seconds

# Event IDs to Monitor
FAILED_LOGIN_ID = 4625
PRIVILEGE_ESCALATION_ID = 4672

# Failed logins tracker
failed_login_count = 0
alert_sent_failed_login = False  # Flag for failed login passing threshold
alert_sent_privilege = False  # Flag for any privilege escalation activity


def send_email_alert(subject, body, recipient=None):
    """Send an email or text alert with a custom sender alias."""
    recipient = recipient or TO_EMAIL  # Default to email if no recipient specified
    msg = MIMEText(body, "html")
    msg["From"] = f"PySIEM Alert <{EMAIL_ADDRESS}>"
    msg["To"] = recipient
    msg["Subject"] = subject

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, recipient, msg.as_string())
        server.quit()
        print(f"[INFO] Alert sent to {recipient}: {subject}")
    except Exception as e:
        print(f"[ERROR] Failed to send alert to {recipient}: {e}")


def format_event_details(event, message):
    """Format the event details for email alerts."""
    return f"""
    <h3>An account failed to log on.</h3>
    <p><strong>Event Time:</strong> {event.TimeGenerated.Format()}</p>
    <pre>{message}</pre>
    """


def monitor_windows_logs():
    """Monitor Windows Security Logs for failed logins and privilege escalation."""
    global failed_login_count, alert_sent_failed_login, alert_sent_privilege
    server = "localhost"
    logtype = "Security"
    print("Monitoring Security logs...")

    hand = win32evtlog.OpenEventLog(server, logtype)
    flags = win32con.EVENTLOG_BACKWARDS_READ | win32con.EVENTLOG_SEQUENTIAL_READ

    last_reset_time = time.time()

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                message = win32evtlogutil.SafeFormatMessage(event, logtype)

                # Failed Logins IF (Event ID 4625)
                if event.EventID == FAILED_LOGIN_ID:
                    failed_login_count += 1
                    print(f"[ALERT] Failed login detected at {event.TimeGenerated.Format()}")

                    if failed_login_count == EMAIL_LOGIN_THRESHOLD and not alert_sent_failed_login:
                        subject = "Alert: Multiple Failed Login Attempts"
                        body = format_event_details(event, message)
                        send_email_alert(subject, body)
                        alert_sent_failed_login = True
                        print(f"[DEBUG] Email alert sent to {TO_EMAIL} after 3 failed attempts.")

                    if failed_login_count == FAILED_LOGIN_THRESHOLD and not alert_sent_failed_login:
                        subject = "Critical: Brute Force Detected"
                        body = format_event_details(event, message)
                        send_email_alert(subject, body)  # Email alert
                        send_email_alert(subject, body, recipient=TEXT_EMAIL)  # Text alert
                        alert_sent_failed_login = True
                        print(f"[DEBUG] Email and text alerts sent after 5 failed attempts.")

                # Privilege Escalation IF (Event ID 4672)
                elif event.EventID == PRIVILEGE_ESCALATION_ID:
                    if not alert_sent_privilege:
                        print(f"[ALERT] Privilege escalation detected at {event.TimeGenerated.Format()}")
                        subject = "Alert: Privilege Escalation Detected"
                        body = format_event_details(event, message)
                        send_email_alert(subject, body)
                        alert_sent_privilege = True
                        print(f"[DEBUG] Privilege escalation email sent to {TO_EMAIL}.")

        # Reset failed login count and flags after reset time
        if time.time() - last_reset_time > FAILED_LOGIN_RESET_TIME:
            failed_login_count = 0
            alert_sent_failed_login = False
            alert_sent_privilege = False  # Reset privilege escalation flag
            last_reset_time = time.time()
            print("[INFO] Reset failed login count and alert flags.")

        time.sleep(10)


if __name__ == "__main__":
    try:
        monitor_windows_logs()
    except KeyboardInterrupt:
        print("\n[INFO] Log monitoring stopped.")
