# your_app/management/commands/send_daily_notifications.py
from django.core.management.base import BaseCommand
from Myapp.notifications import send_daily_notifications

class Command(BaseCommand):
    help = 'Send daily notification email to all active users'

    def handle(self, *args, **options):
        count = send_daily_notifications()
        if count:
            self.stdout.write(self.style.SUCCESS(
                f'Success: sent notifications to {count} users.'
            ))
        else:
            self.stdout.write(self.style.WARNING('No active users found.'))
