import time
from datetime import timedelta
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

def notification_scheduler():
    target_hour = 22   # 10 PM in 24-hour format
    target_minute = 0  # 00 minutes

    while True:
        # Get the current time in the timezone of the app
        now = timezone.localtime(timezone.now())

        # Set the target time for today
        today_target = now.replace(hour=target_hour, minute=target_minute, second=0, microsecond=0)

        if now >= today_target:
            # If the target time for today has passed, schedule for tomorrow
            next_target = today_target + timedelta(days=1)
        else:
            # Otherwise, schedule for today
            next_target = today_target

        # Calculate the time in seconds until the next target time (subtract 60 seconds for the check)
        seconds_until_next = (next_target - now).total_seconds() - 30  # Checking 1 minute before target time

        if seconds_until_next < 1:
            print(f"{seconds_until_next} left [Scheduler] to reach Target time {next_target}, executing immediately!")
            time.sleep(1)  # Sleep a minimal second to stabilize
        else:
            print(f"[Scheduler] Sleeping for {int(seconds_until_next)} seconds until {next_target}")
            time.sleep(seconds_until_next)

        # Wait for the exact time, checking every second
        while timezone.localtime(timezone.now()) < next_target:
            time.sleep(1)

        # Send the notification
        send_daily_notifications()
        print("Notifications sent successfully!")
