import redis
from django.conf import settings
from rest_framework.permissions import BasePermission

redis_instance = redis.Redis.from_url(settings.CACHES["default"]["LOCATION"])


class IsTokenBlacklisted(BasePermission):
    """
    Permission class that denies access if the provided JWT token is blacklisted.

    Checks the 'Authorization' header for a Bearer token. If the token exists in the Redis blacklist,
    permission is denied. Otherwise, permission is granted.

    Attributes:
        message (str): Error message returned when permission is denied.

    Methods:
        has_permission(request, view) -> bool:
            Returns True if the token is not blacklisted; otherwise, returns False.
    """

    message = "Invalid token"

    def has_permission(self, request, view) -> bool:
        auth_header = request.headers.get("Authorization", "")

        if not auth_header:
            return False

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False

        token = parts[1]
        if redis_instance.exists(token):
            return False

        return True
