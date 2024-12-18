# PySIEM

Obviously not a SIEM lol, but this script sends you an alert in response to a possible brute force attack on your host.

3 failed passwords: An email gets sent letting you know of the irregular login attempts.

5 failed passwords: A text message will be sent to your phone regarding the suspicious activity. (Optional)

Most major phone carriers have a function where you can use your email to send text messages to yourself.  
I thought it would be cool to implement it in scripts and some automation stuff.

Read more about it here: [https://20somethingfinance.com/how-to-send-text-messages-sms-via-email-for-free/](https://20somethingfinance.com/how-to-send-text-messages-sms-via-email-for-free/)

Background:
Start-Process -FilePath "python" -ArgumentList ".\PySIEM.py" -WindowStyle Hidden
