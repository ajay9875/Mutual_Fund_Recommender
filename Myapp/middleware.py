# Myapp/middleware.py
from django.contrib.auth import logout
from django.utils import timezone
from django.contrib.sessions.models import Session
from django.core.exceptions import MiddlewareNotUsed

class AutoLogoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if the user is authenticated
        if request.user.is_authenticated:
            # Get the session key from the request
            session_key = request.session.session_key

            try:
                # Get the session object from the database
                session = Session.objects.get(session_key=session_key)
                # Check if the session has expired
                if timezone.now() > session.expire_date:
                    # Log out the user if the session has expired
                    logout(request)
            except Session.DoesNotExist:
                # If the session does not exist, log out the user
                logout(request)

        # Continue processing the request
        response = self.get_response(request)
        return response