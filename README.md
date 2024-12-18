# PySIEM

Lightweight security monitoring script designed for Windows environments

Monitors Windows Logs for failed login attempts and privilege escalation, sends an email and/or text alerts for suspicious activity

---

3 failed passwords: An email alert is sent

5 failed passwords: A text message is sent

Most major phone carriers have a function where you can use your email to send text messages to yourself.
However, it's not incredibly quick or "real-time", as the message must traverse Google's and the phone company's servers before it reaches you.
But I thought it would be interesting to implement it

Read more: [https://20somethingfinance.com/how-to-send-text-messages-sms-via-email-for-free/](https://20somethingfinance.com/how-to-send-text-messages-sms-via-email-for-free/)

## Features

- Alerts for failed login attempts (Event ID 4625)
- Alerts for privilege escalation events (Event ID 4672)
- Customizable thresholds for failed login attempts
- Sends email and optional text alerts

## Requirements

1. Python 3.10 or newer installed on the system
2. The `pywin32` pyhton
3. A Gmail account
4. Administrator access to the system to monitor Windows Event Logs

---

## Setup Instructions

### 1. Generate and document a Google [App Password](https://support.google.com/accounts/answer/185833?hl=en)
Make sure you document it in your notes, because you can only see it once it is generated

---

### 2. Clone the Repository

Open **PowerShell as Administrator**, then run:

```powershell
git clone <url>
cd Security-Alert-Script

```

---

### 3. Bypass Script Execution Policy
```powershell
Get-ExecutionPolicy
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
Hit Y for yes

---

### 4. Run the setup script

Change to script directory:
```powershell
cd Security-Alert-Script
```
This copies the PySIEM.py file to your Desktop:
```powershell
./setup.ps1
```

---

### 5. Open up the PySIEM script
Open with any python text editor

![Screenshot 2024-12-18 at 12 09 15](https://github.com/user-attachments/assets/45313f20-e502-4088-bbf6-218ac4af3499)

---

### 6. Edit script
Again, the carrier's email to gateway is optional

![Screenshot 2024-12-18 at 12 20 40](https://github.com/user-attachments/assets/1221b666-54dc-4587-898f-70ec45f54f8f)

File -> Save
---

### 7. Install Dependencies (Still in Powershell)
```powershell
pip install -r requirements.txt
```

---

### 8. Setup Monitoring
Open Task Scheduler

![Screenshot 2024-12-18 at 12 36 23](https://github.com/user-attachments/assets/dada1c2f-e5ee-408a-a44e-f19c2a48a3b8)

Create a new task

![Screenshot 2024-12-18 at 12 38 37](https://github.com/user-attachments/assets/f74f5b90-ea8c-4da1-9946-eb189ad55dcb)

General

![Screenshot 2024-12-18 at 12 43 03](https://github.com/user-attachments/assets/4158bf22-14dc-4b67-bcf7-0c699c7aa8c6)


Triggers

![Screenshot 2024-12-18 at 12 43 31](https://github.com/user-attachments/assets/d1751426-9874-4175-ac94-6d26944d44b9)


Actions - enter the Desktop path to PySIEM

![Screenshot 2024-12-18 at 12 43 54](https://github.com/user-attachments/assets/8e9dacbd-803a-4512-ab25-e54dd01d488f)


Conditions - Configure as needed, expecially the power section if you are on a laptop

![Screenshot 2024-12-18 at 12 44 09](https://github.com/user-attachments/assets/abd27639-d21f-44dc-ab94-a7448d73fa1e)


Settings

![Screenshot 2024-12-18 at 12 45 36](https://github.com/user-attachments/assets/0caab84e-c37a-4f2d-b10f-8ed131bf5dc1)


Ok -> Enter your password

------

### Troubleshooting
 Script failed to run? Ensure you’ve adjusted the execution policy to allow scripts:

    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

Not receiving alerts? Verify email credentials and spam folder

Too many alerts? Ensure you’re triggering only the specified Event IDs (4625 for failed logins, 4672 for privilege escalation)


---
Feel free to submit issues or pull requests to improve functionality or documentation

This project is licensed under the MIT License

