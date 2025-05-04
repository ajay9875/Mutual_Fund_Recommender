from pathlib import Path
from django.contrib.messages import constants as messages

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-p7bv-03i&pdm0e&f_ce_=y5d$_2xbdj90xelz$fl-*3vb#4@)0'

# Ensure DEBUG is True for development
DEBUG = True
 
# SECURITY WARNING: don't run with debug turned on in production!
ALLOWED_HOSTS = []

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
    "django.contrib.sessions.middleware.SessionMiddleware",  # ✅ Must come before AuthenticationMiddleware
    "django.contrib.auth.middleware.AuthenticationMiddleware",  # ✅ Required for request.user
    'django.middleware.security.SecurityMiddleware',
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
USE_TZ = True  # Keep Django aware of time zones

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

# Manualy Imported
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STATIC_URL = '/static/'  # URL for serving static files

# Optional: Define Global Static Files Directory
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),  # For a project-wide static folder
]

# Required in Production for `collectstatic`
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

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
EMAIL_HOST_USER = "mutualfundrecommendation@gmail.com"  # Replace with your Gmail ID
EMAIL_HOST_PASSWORD = "mstc ewzm gmdc fdyp"  # Replace with App Password from Step 1
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER  # Default email sender

# Set session timeout to 10 minutes
SESSION_COOKIE_AGE = 360

# Ensure sessions do not expire when the browser is closed
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# Disable session extension on every request
SESSION_SAVE_EVERY_REQUEST = False

MEDIA_URL = "/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")

# Serve media files in development
if DEBUG:
    from django.conf.urls.static import static
    MEDIAFILES = static(MEDIA_URL, document_root=MEDIA_ROOT)
else:
    MEDIAFILES = []

# Optional: Set the error pages explicitly
ERROR_404_TEMPLATE = '404.html'