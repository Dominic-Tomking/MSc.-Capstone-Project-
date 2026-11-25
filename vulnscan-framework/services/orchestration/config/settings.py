"""Django settings for the vulnscan orchestration service.

The Django application is intentionally thin: it coordinates and displays; it
does not perform detection (proposal S4.1).  It persists contracts, scans,
findings, labels and metrics in PostgreSQL, exposes a REST API, and dispatches
asynchronous analysis tasks to Celery workers.

For local development / CI without Postgres and Redis, a SQLite database and an
eager (in-process) Celery mode are used automatically.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Make the top-level `vulnscan` package importable from the orchestration app.
REPO_ROOT = BASE_DIR.parent.parent
for p in (str(REPO_ROOT),):
    if p not in sys.path:
        sys.path.insert(0, p)

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-insecure-key-change-me")
DEBUG = os.environ.get("DJANGO_DEBUG", "1") == "1"
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.debug",
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]

# --- Database: Postgres in production, SQLite fallback for dev/CI ------------
if os.environ.get("POSTGRES_HOST"):
    DATABASES = {"default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "vulnscan"),
        "USER": os.environ.get("POSTGRES_USER", "vulnscan"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "vulnscan"),
        "HOST": os.environ["POSTGRES_HOST"],
        "PORT": os.environ.get("POSTGRES_PORT", "5432"),
    }}
else:
    DATABASES = {"default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }}

# --- Celery / Redis ---------------------------------------------------------
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL
# Run tasks synchronously in-process when no broker is configured (dev/CI).
CELERY_TASK_ALWAYS_EAGER = os.environ.get("CELERY_EAGER", "0") == "1"

REST_FRAMEWORK = {
    "DEFAULT_PAGINATION_CLASS":
        "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
}

AUTH_PASSWORD_VALIDATORS = []
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_TZ = True
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Toggle: call the static-analysis microservice over HTTP, or run in-process.
STATIC_ANALYSIS_MODE = os.environ.get("STATIC_ANALYSIS_MODE", "inprocess")
STATIC_ANALYSIS_URL = os.environ.get("STATIC_ANALYSIS_URL", "http://static-analysis:8100")
