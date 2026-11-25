"""Ensure the Celery app is loaded when Django starts."""
try:
    from .celery import app as celery_app  # noqa: F401
    __all__ = ["celery_app"]
except Exception:  # pragma: no cover - celery optional in some contexts
    __all__ = []
