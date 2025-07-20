from django.test import TestCase

from accounts.models import User
from accounts.serializers import (
    EmailChangeSerializer,
    PasswordChangeSerializer,
    UserLoginSerializer,
    UserRegisterSerializer,
    UserUpdateSerializer,
)


class UserRegisterSerializerTest(TestCase):
    """
    Test suite for the UserRegisterSerializer.
    This test class contains unit tests to validate the behavior of the UserRegisterSerializer
    when handling user registration data. It ensures that the serializer correctly validates
    and processes input data, including username and password constraints.

    Tests:
    - test_valid_data_creates_user: Verifies that valid data creates a user successfully.
    - test_username_starts_with_number_invalid: Ensures usernames starting with a number are invalid.
    - test_username_starts_with_underscore_invalid: Ensures usernames starting with an underscore are invalid.
    - test_username_ends_with_underscore_invalid: Ensures usernames ending with an underscore are invalid.
    - test_username_contains_invalid_chars: Ensures usernames containing invalid characters are rejected.
    - test_password_missing_uppercase: Ensures passwords missing an uppercase letter are invalid.
    - test_password_missing_lowercase: Ensures passwords missing a lowercase letter are invalid.
    - test_password_missing_digit_or_symbol: Ensures passwords missing a digit or symbol are invalid.

    Setup:
    - Initializes valid user registration data for use in tests.
    """

    def setUp(self):
        self.valid_data = {
            "username": "valid_user",
            "email": "valid@example.com",
            "password": "StrongPass1!",
        }

    def test_valid_data_creates_user(self):
        serializer = UserRegisterSerializer(data=self.valid_data)
        self.assertTrue(serializer.is_valid())
        user = serializer.save()
        self.assertEqual(user.username, self.valid_data["username"])
        self.assertEqual(user.email, self.valid_data["email"])

    def test_username_starts_with_number_invalid(self):
        data = self.valid_data.copy()
        data["username"] = "1user"
        serializer = UserRegisterSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("username", serializer.errors)

    def test_username_starts_with_underscore_invalid(self):
        data = self.valid_data.copy()
        data["username"] = "_user"
        serializer = UserRegisterSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("username", serializer.errors)

    def test_username_ends_with_underscore_invalid(self):
        data = self.valid_data.copy()
        data["username"] = "user_"
        serializer = UserRegisterSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("username", serializer.errors)

    def test_username_contains_invalid_chars(self):
        data = self.valid_data.copy()
        data["username"] = "invalid$user"
        serializer = UserRegisterSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("username", serializer.errors)

    def test_password_missing_uppercase(self):
        data = self.valid_data.copy()
        data["password"] = "weakpass1!"
        serializer = UserRegisterSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)

    def test_password_missing_lowercase(self):
        data = self.valid_data.copy()
        data["password"] = "WEAKPASS1!"
        serializer = UserRegisterSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)

    def test_password_missing_digit_or_symbol(self):
        data = self.valid_data.copy()
        data["password"] = "PasswordOnly"
        serializer = UserRegisterSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)
