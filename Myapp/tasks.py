from celery import shared_task
from .notifications import send_daily_notifications

@shared_task
def send_daily_notifications_task():
    count = send_daily_notifications()
    return f"Sent to {count} users."
