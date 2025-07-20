import re

from rest_framework import serializers

from .models import User


class UserRegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.

    Validates the following:
    - Username must contain only lowercase letters, numbers, and underscores.
    - Username cannot start with a number.
    - Username cannot start or end with an underscore.
    - Password must be 8-32 characters, write-only, and include:
        - At least one uppercase letter.
        - At least one lowercase letter.
        - At least one digit or special character (@ _ - # ! * / . , | ( ) = +).

    Creates a new user using Django's `create_user` method.
    """

    class Meta:
        model = User
        fields = ["username", "email", "password"]

        extra_kwargs = {
            "password": {"min_length": 8, "max_length": 32, "write_only": True},
        }

    def validate(self, data):
        if not re.match(r"^[a-z0-9_]*$", data["username"]):
            raise serializers.ValidationError(
                {
                    "username": "Username must contain only lowercase letters, numbers, and underscores."
                }
            )

        if data.get("username")[0].isnumeric():
            raise serializers.ValidationError(
                {"username": "Username can't start with a number"}
            )

        if data.get("username")[0] == "_" or data.get("username")[-1] == "_":
            raise serializers.ValidationError(
                {"username": "Username can't start or end with a underscore"}
            )

        if not re.search(r"[A-Z]", data["password"]):
            raise serializers.ValidationError(
                {"password": "Password must include at least one uppercase letter."}
            )

        if not re.search(r"[a-z]", data["password"]):
            raise serializers.ValidationError(
                {"password": "Password must include at least one lowercase letter."}
            )

        if not re.search(r"[0-9@_\-#!*/.,|()=+]", data["password"]):
            raise serializers.ValidationError(
                {
                    "password": "Password must include at least one digit or special character."
                }
            )

        return data

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user login.

    Requires:
    - Username (max 32 characters)
    - Password (write-only)
    """

    username = serializers.CharField(max_length=32, required=True)
    password = serializers.CharField(write_only=True, required=True)


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating a user's username.

    Validates that the username:
    - Contains only letters (uppercase and lowercase), numbers, and underscores.
    - Does not start with a number.
    - Does not start or end with an underscore.

    Raises:
        serializers.ValidationError: If the username does not meet the validation criteria.
    """

    class Meta:
        model = User
        fields = ["username"]

    def validate_username(self, value):
        if value:
            if not re.match(r"^[a-zA-Z0-9_]*$", value):
                raise serializers.ValidationError(
                    {
                        "username": "Username must contain only lowercase letters, uppercase letters, numbers, and underscores."
                    }
                )

            if value[0].isnumeric():
                raise serializers.ValidationError(
                    {"username": "Username can't start with a number"}
                )

            if value[0] == "_" or value[-1] == "_":
                raise serializers.ValidationError(
                    {"username": "Username can't start or end with a underscore"}
                )

        return value


class EmailChangeSerializer(serializers.Serializer):
    """
    Serializer for handling email change requests.

    Fields:
        new_email (EmailField): The new email address to be set for the user.

    Validations:
        - Ensures the new email is not already in use by another user.

    Raises:
        serializers.ValidationError: If the provided email is already associated with an existing user.
    """

    new_email = serializers.EmailField(max_length=254)

    def validate_new_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email already in use")
        return value


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for handling password change requests via email.

    Fields:
        email (EmailField): The email address of the user requesting a password change.

    Methods:
        validate_email(value):
            Validates that a user with the provided email exists.
            Raises a ValidationError if no user is found with the given email.
    """

    email = serializers.EmailField(max_length=254)

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email was not found")
        return value
