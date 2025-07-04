import os
from decouple import config
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config("SECRET_KEY")

# Ensure DEBUG is True for development not for deployment
DEBUG = False

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': '/tmp/django_cache',  # Change to a suitable path
    }
}

# SECURITY WARNING: don't run with debug turned on in production!
#ALLOWED_HOSTS = []
# Base allowed hosts (development defaults)
BASE_ALLOWED_HOSTS = [
    'localhost',
    '127.0.0.1',
]

# Environment variable hosts (production)
ENV_HOSTS = os.getenv('ALLOWED_HOSTS', '').split(',')

# Combine both lists and filter empty strings
ALLOWED_HOSTS = [host for host in [*BASE_ALLOWED_HOSTS, *ENV_HOSTS] if host]

# Application definition
INSTALLED_APPS = [
    #'Myapp',
    'Myapp.apps.MyappConfig',  # Add the app to the list of installed apps
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # ← Must be 2nd
    "django.contrib.sessions.middleware.SessionMiddleware",  # ✅ Must come before AuthenticationMiddleware
    "django.contrib.auth.middleware.AuthenticationMiddleware",  # ✅ Required for request.user
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    "django.contrib.messages.middleware.MessageMiddleware",  # Required for flash messages
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'Myproject.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [], # No need to add templates directory here because Django will automatically look for templates directory in each app.
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'Myproject.wsgi.application'

# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
        'OPTIONS': {
            'timeout': 20,
        },
        'ATOMIC_REQUESTS': False,
    }
}

# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'
USE_TZ = True # Keep Django aware of time zones

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

# Manualy Imported
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# KEEP ONLY ONE COPY OF THESE (remove duplicates):
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')  # For collectstatic
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]  # Your source files
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# All setup to send mail to reset username and password
# Email Configuration
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"  # Use Gmail's SMTP server
EMAIL_PORT = 587  # SMTP Port (Use 465 if using SSL)
EMAIL_USE_TLS = True  # Enable TLS encryption
EMAIL_USE_SSL = False  # SSL should be False when TLS is True
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER  # Default email sender

# Consistent 30-minute (1800s) timeout
SESSION_COOKIE_AGE = 1800  # 30 minutes in seconds
SESSION_SAVE_EVERY_REQUEST = True  # Renew timer on activity
SESSION_EXPIRE_AT_BROWSER_CLOSE = False  # Use persistent sessions

MEDIA_URL = "/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")

# Serve media files in development
if DEBUG:
    from django.conf.urls.static import static
    MEDIAFILES = static(MEDIA_URL, document_root=MEDIA_ROOT)
else:
    MEDIAFILES = []

SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Whitenoise compression and caching
WHITENOISE_MANIFEST_STRICT = False
WHITENOISE_MAX_AGE = 31536000  # 1 year cache

# Optional: Set the error pages explicitly
ERROR_404_TEMPLATE = '404.html'