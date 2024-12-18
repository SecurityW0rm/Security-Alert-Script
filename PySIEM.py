import time
import smtplib
from email.mime.text import MIMEText
import win32evtlog  # For reading Windows Event Logs
import win32evtlogutil
import win32con
from collections import defaultdict

#================================================================EDIT BELOW HERE==================================================================================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "EMAIL@gmail.com" # Enter your gmail, I recommend creating one at least just for alerts
EMAIL_PASSWORD = "App Password" # The app password generated in gmail admin settings (search for "App Password" on https://myaccount.google.com/)
TO_EMAIL = "EMAIL@gmail.com" # Enter your gmail again
TEXT_EMAIL = "PHONE@carrier_server.com"  # OPTIONAL: Input your carrier's email-to-text gateway -> phoneNumber@carrier_gateway.com
                                         # Read more: https://20somethingfinance.com/how-to-send-text-messages-sms-via-email-for-free/

#================================================================EDIT ABOVE HERE==================================================================================

# Login Attempt Threshold Triggers
FAILED_LOGIN_THRESHOLD = 3
TEXT_NOTIFICATION_THRESHOLD = 5
FAILED_LOGIN_RESET_TIME = 60  # Resets the count after 60 seconds

# Event IDs to look for
FAILED_LOGIN_ID = 4625
PRIVILEGE_ESCALATION_ID = 4672

# Login attempt counter
failed_login_count = 0
failed_login_ips = defaultdict(int)  # Count failed logins by IP address


# Email phase 1, setup structure
def send_email(subject, body, recipient):
    msg = MIMEText(body, "html")
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = recipient
    msg["Subject"] = subject

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, recipient, msg.as_string())
        server.quit()
        print(f"[INFO] Email sent to {recipient}: {subject}")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")


# Function to monitor logs
def monitor_windows_logs():
    global failed_login_count
    server = "localhost"
    logtype = "Security"
    print("Monitoring Security logs for failed logins and privilege escalations...")

    hand = win32evtlog.OpenEventLog(server, logtype)
    flags = win32con.EVENTLOG_BACKWARDS_READ | win32con.EVENTLOG_SEQUENTIAL_READ

    last_reset_time = time.time()

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                event_time = event.TimeGenerated.Format()
                message = win32evtlogutil.SafeFormatMessage(event, logtype)

                if event.EventID == FAILED_LOGIN_ID:
                    # Failed login attempt detected
                    failed_login_count += 1
                    ip_address = extract_ip_address(message)
                    failed_login_ips[ip_address] += 1
                    print(f"[ALERT] Failed login attempt detected at {event_time} from {ip_address}")

                    # Send an email alert when threshold (3) is exceeded
                    if failed_login_count == FAILED_LOGIN_THRESHOLD:
                        subject = "Alert: Multiple Failed Login Attempts"
                        body = f"""
                        <h3>Failed Login Alert</h3>
                        <p><strong>Event Time:</strong> {event_time}</p>
                        <p><strong>Failed Attempts:</strong> {failed_login_count}</p>
                        <p><strong>IP Addresses:</strong> {dict(failed_login_ips)}</p>
                        """
                        send_email(subject, body, TO_EMAIL)

                    # Send a text alert if threshold (5) when exceeded
                    if failed_login_count == TEXT_NOTIFICATION_THRESHOLD:
                        subject = "Critical: Brute Force Detected"
                        body = f"Brute Force Detected: {failed_login_count} failed attempts from {dict(failed_login_ips)}"
                        send_email(subject, body, TEXT_EMAIL)

                elif event.EventID == PRIVILEGE_ESCALATION_ID:
                    # Privilege escalation detected
                    print(f"[ALERT] Privilege escalation detected at {event_time}")
                    subject = "Alert: Privilege Escalation Detected"
                    body = f"""
                    <h3>Privilege Escalation Alert</h3>
                    <p><strong>Event Time:</strong> {event_time}</p>
                    <p><strong>Details:</strong><br><pre>{message}</pre></p>
                    """
                    send_email(subject, body, TO_EMAIL)

        # Reset failed login count after the reset time
        if time.time() - last_reset_time > FAILED_LOGIN_RESET_TIME:
            failed_login_count = 0
            failed_login_ips.clear()
            last_reset_time = time.time()

        time.sleep(10)


# Function to extract IP address from event message
def extract_ip_address(message):
    import re
    ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    match = ip_pattern.search(message)
    return match.group(1) if match else "No IP Found"


if __name__ == "__main__":
    try:
        monitor_windows_logs()
    except KeyboardInterrupt:
        print("\n[INFO] Log monitoring stopped.")