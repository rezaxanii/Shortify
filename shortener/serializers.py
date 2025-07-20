from rest_framework import serializers

from .models import Shortener


class ShortenerSerializer(serializers.ModelSerializer):
    """
    Serializer for the Shortener model, handling URL shortening functionality.

    Fields:
        - id (read-only): Unique identifier for the shortened URL.
        - url: The original URL to be shortened.
        - short_code (read-only): The generated short code for the URL.
        - password (write-only): Optional password to protect the shortened URL.
        - created_at (read-only): Timestamp when the shortened URL was created.
        - expires_at (read-only): Timestamp when the shortened URL will expire.
        - views (read-only): Number of times the shortened URL has been accessed.

    Validations:
        - Ensures that only authenticated users can set a password for a shortened URL.

    Notes:
        - Password field is write-only for security.
        - Read-only fields cannot be modified via API requests.
    """

    class Meta:
        model = Shortener
        fields = [
            "id",
            "url",
            "short_code",
            "password",
            "created_at",
            "expires_at",
            "views",
        ]
        read_only_fields = ["id", "short_code", "created_at", "expires_at", "views"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate_password(self, value):
        user = self.context["request"].user
        if not user.is_authenticated and value is not None:
            raise serializers.ValidationError("You must be logged in to set a password")
        return value


class ShortenerDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for detailed representation of the Shortener model.

    Fields:
        url (str): The original URL to be shortened.
        short_code (str): The generated short code for the URL.
        created_at (datetime): Timestamp when the shortener entry was created.
        expires_at (datetime): Timestamp when the shortener entry will expire.
        views (int): Number of times the shortened URL has been accessed.
        password (str): Optional password required to access the shortened URL.
        available (bool): Indicates if the shortened URL is currently available.
    """

    class Meta:
        model = Shortener
        fields = [
            "url",
            "short_code",
            "created_at",
            "expires_at",
            "views",
            "password",
            "available",
        ]


class ShortenerUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating Shortener instances.

    Allows partial updates of the following fields:
    - url: The original URL to be shortened (optional).
    - password: Optional password for accessing the shortened URL.
    - available: Boolean indicating if the shortened URL is active (optional).

    All fields are optional for update operations.
    """

    class Meta:
        model = Shortener
        fields = ["url", "password", "available"]
        extra_kwargs = {
            "url": {"required": False},
            "available": {"required": False},
            "password": {"required": False},
        }
