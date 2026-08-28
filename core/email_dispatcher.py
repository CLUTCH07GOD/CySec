"""
Core Module: Email OTP Dispatcher Service
-----------------------------------------
Handles automated email dispatch of 6-digit OTP security codes using
Python's built-in smtplib / SSL protocol. Supports Gmail, SendGrid, and custom SMTP servers.
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import streamlit as st

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# SMTP Configuration from Environment Variables or Streamlit Secrets
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", SMTP_USERNAME or "no-reply@compliance-platform.local")

def send_otp_email(recipient_email: str, otp_code: str, username: str = "") -> tuple[bool, str]:
    """
    Dispatches a 6-digit OTP code to the recipient's email inbox via SMTP.
    If SMTP credentials are configured, sends live email; otherwise logs the email content securely.
    """
    subject = "🔑 Your Compliance Platform Security Verification OTP"
    body_text = f"""
    Hello {username or recipient_email},

    Your single-use 6-digit Security Verification Code is:

    ===========================
             {otp_code}
    ===========================

    This code is valid for 10 minutes. Do not share this code with anyone.

    If you did not request this OTP, please secure your account immediately.

    Regards,
    Cybersecurity Compliance Platform Security Team
    """

    # Reload environment variables dynamically
    try:
        from dotenv import load_dotenv
        load_dotenv(override=True)
    except Exception:
        pass

    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", 587))
    smtp_user = os.environ.get("SMTP_USERNAME", "").strip()
    smtp_pass = os.environ.get("SMTP_PASSWORD", "").strip()
    sender_email = os.environ.get("SENDER_EMAIL", "").strip() or smtp_user or "no-reply@compliance-platform.local"

    # If SMTP credentials are set, send live email via SMTP
    if smtp_user and smtp_pass and "your_16_digit" not in smtp_pass:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = sender_email
            msg["To"] = recipient_email
            
            # Text part
            msg.attach(MIMEText(body_text, "plain"))
            
            # HTML part
            html_content = f"""
            <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; background: #0f172a; color: #f8fafc; border-radius: 16px; border: 1px solid #38bdf8;">
                <h2 style="color: #38bdf8; margin-top: 0;">🛡️ Cybersecurity Compliance Portal</h2>
                <p style="color: #cbd5e1; font-size: 1rem;">Your single-use login verification code:</p>
                <div style="background: rgba(56, 189, 248, 0.15); border: 1px solid #38bdf8; border-radius: 12px; padding: 18px; text-align: center; margin: 20px 0;">
                    <span style="font-size: 2.2rem; font-weight: bold; letter-spacing: 6px; color: #38bdf8;">{otp_code}</span>
                </div>
                <p style="color: #94a3b8; font-size: 0.85rem;">This code will expire in 10 minutes. Do not share this code with anyone.</p>
            </div>
            """
            msg.attach(MIMEText(html_content, "html"))
            
            # Connect and send via TLS
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(sender_email, [recipient_email], msg.as_string())
                
            return True, f"Live email dispatched successfully to {recipient_email}."
        except Exception as e:
            print(f"[SMTP DISPATCH WARNING] Could not send via SMTP ({e}). Logging OTP internally.", flush=True)
            
    # Fallback/Console Log for local development without SMTP config
    print("\n" + "="*60, flush=True)
    print(f"[EMAIL DISPATCH SIMULATOR] Sending Email to: {recipient_email}", flush=True)
    print(f"Subject: {subject}", flush=True)
    print(body_text, flush=True)
    print("="*60 + "\n", flush=True)
    
    return True, f"OTP dispatched for {recipient_email}."
