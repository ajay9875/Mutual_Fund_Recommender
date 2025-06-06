from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

admin.site.site_header = "Mutual Fund Recommendation: Admin" 
admin.site.site_title = "Mutual Fund Admin Portal" 
admin.site.index_title = "Welcome to Admin Panel"

urlpatterns = [
    path('admin/', admin.site.urls),
    path("", include("Myapp.urls")),
]

from django.conf import settings
from django.conf.urls.static import static

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
