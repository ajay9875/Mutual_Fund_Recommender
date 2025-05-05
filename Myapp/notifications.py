import time
from datetime import datetime
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()

from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()

def send_daily_notifications():
    """
    Send personalized daily update emails to all active users.
    """
    users = User.objects.filter(is_active=True).exclude(email__isnull=True)

    subject = '🔷 Mutual Fund Recommendation — Your Daily Update'

    sent_count = 0

    for user in users:
        full_name = f"{user.first_name} {user.last_name}".strip() or "Investor"
        recipient_email = user.email

        html_message = f"""
        <html><body>
            <h2>Hello {full_name},</h2>
            <p>Welcome to your daily update from the 🔷 Mutual Fund Recommendation System.</p>
            <p>Here's what's happening today:</p>
            <ul>
                <li><strong>Top-performing funds</strong> handpicked for you</li>
                <li><strong>Latest market trends</strong> to keep you informed</li>
                <li><strong>Investment tips</strong> to grow your portfolio</li>
            </ul>
            <p><a href="https://mutual-fund-recommender.onrender.com/login">Log in</a> to view your personalized dashboard and recommendations.</p>
            <br>
            <p>Warm regards,</p>
            <p><strong>🔷 Mutual Fund Recommendation Team</strong></p>
            <hr>
            <p style="font-size:0.8em;color:#666;">
               You’re receiving this email because you're registered with the 🔷 Mutual Fund Recommendation System.
            </p>
        </body></html>
        """

        send_mail(
            subject=subject,
            message='',  # fallback plain-text message (optional)
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[recipient_email],
            html_message=html_message,
            fail_silently=False,
        )
        sent_count += 1

    return sent_count

def notification_scheduler():
    """
    Scheduler function to send daily notifications at 09:00 AM.
    Runs in a separate thread.
    """
    sent_today = False
    while True:
        now = datetime.now()
        # Check if it's 4:10 PM
        if now.hour == 18 and now.minute == 10:
            if not sent_today:
                send_daily_notifications()  # Send email notifications
                sent_today = True
        else:
            sent_today = False  # Reset the flag after 4:10 PM

        time.sleep(5)  # Sleep for 1 minute before checking again
