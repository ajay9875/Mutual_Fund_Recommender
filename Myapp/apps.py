from django.apps import AppConfig
import threading

class MyappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Myapp'

    def ready(self):
        from .notifications import notification_scheduler
        threading.Thread(target=notification_scheduler, daemon=True).start()
