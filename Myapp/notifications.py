import time
from datetime import datetime
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()

def send_daily_notifications():
    """
    Grab all active users and send them the daily email.
    """
    recipient_list = list(
        User.objects.filter(is_active=True)
            .exclude(email__isnull=True)
            .values_list('email', flat=True)
    )
    if not recipient_list:
        return 0

    subject = '🔷 Mutual Fund Recommendation — Your Daily Update'
    html_message = """
    <html><body>
        <h2>Hello from 🔷 Mutual Fund Recommendation System!</h2>
        <p>Here’s your daily market snapshot and curated tips:</p>
        <ul>
            <li>Top-performing funds of the day</li>
            <li>Market news highlights</li>
            <li>Investment reminder: review your portfolio</li>
        </ul>
        <p>Log in to your dashboard for full details!</p>
        <hr>
        <p style="font-size:0.8em;color:#666;">
           You’re receiving this because you’re registered on 🔷 Mutual Fund Recommendation System.
        </p>
    </body></html>
    """

    send_mail(
        subject=subject,
        message='',  # plain‐text fallback
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=recipient_list,
        html_message=html_message,
        fail_silently=False,
    )
    return len(recipient_list)

def notification_scheduler():
    """
    Scheduler function to send daily notifications at 4:10 PM.
    Runs in a separate thread.
    """
    sent_today = False
    while True:
        now = datetime.now()
        # Check if it's 4:10 PM
        if now.hour == 17 and now.minute == 52:
            if not sent_today:
                send_daily_notifications()  # Send email notifications
                sent_today = True
        else:
            sent_today = False  # Reset the flag after 4:10 PM

        time.sleep(5)  # Sleep for 1 minute before checking again
