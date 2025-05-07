import time
from datetime import datetime, timedelta
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone  # Add timezone to handle time properly in your timezone

User = get_user_model()

def send_daily_notifications():
    """
    Send personalized daily update emails to all active users.
    """
    users = User.objects.filter(is_active=True).exclude(email__isnull=True)

    subject = '🔷 Mutual Fund Recommendation — Your Daily Update'

    sent_count = 0

    for user in users:
        full_name = f"{user.first_name} {user.last_name}".strip() or user.username
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

"""def notification_scheduler():
    sent_today = False
    while True:
        now = timezone.localtime(timezone.now())  # Use Django's timezone to handle the time properly
        # Check if it's the set time (e.g., 9:00 AM or 12:10 PM)
        if now.hour == 12 and now.minute == 28:  # Change to your desired time
            if not sent_today:
                send_daily_notifications()  # Send email notifications
                sent_today = True
        else:
            sent_today = False  # Reset the flag

        time.sleep(60)  # Check every 10 seconds"""

def notification_scheduler():
    target_hour = 9    # Set to 9 for 9:00 AM
    target_minute = 0  # Set to 0 for 9:00 AM

    while True:
        now = timezone.localtime(timezone.now())
        today_target = now.replace(hour=target_hour, minute=target_minute, second=0, microsecond=0)

        if now >= today_target:
            # Target time for today passed, schedule for tomorrow
            next_target = today_target + timedelta(days=1)
        else:
            # Still before today's target time
            next_target = today_target

        seconds_until_next = (next_target - now).total_seconds()

        # Sleep until 30 seconds before next_target
        sleep_time = max(1, seconds_until_next - 30)
        time.sleep(sleep_time)

        # Wait until exact time
        while timezone.localtime(timezone.now()) < next_target:
            time.sleep(1)

        # Time to send notification
        send_daily_notifications()

if __name__ == "__main__":
    notification_scheduler()
