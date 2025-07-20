from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import TestCase
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIRequestFactory

from shortener.models import Shortener
from shortener.serializers import (
    ShortenerDetailSerializer,
    ShortenerSerializer,
    ShortenerUpdateSerializer,
)

User = get_user_model()


class ShortenerSerializerTests(TestCase):
    """
    Tests for the ShortenerSerializer class.
    This test suite verifies the behavior of the ShortenerSerializer under various conditions,
    including validation of input data and handling of authenticated and anonymous users.

    Classes:
        ShortenerSerializerTests: Test cases for the ShortenerSerializer.

    Methods:
        setUp():
            Sets up the test environment, including creating a test user and initializing test data.
        test_valid_data_without_password_for_anonymous_user():
            Tests that an anonymous user can submit valid data without a password and the serializer
            correctly validates the input.
        test_set_password_requires_authenticated_user():
            Tests that an anonymous user cannot set a password when creating a shortened URL,
            and the serializer raises a ValidationError.
        test_authenticated_user_can_set_password():
            Tests that an authenticated user can set a password when creating a shortened URL,
            and the serializer correctly validates the input.
    """

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            username="test_user", email="test@example.com", password="password123"
        )
        self.valid_url = "https://example.com"
        self.test_password = "secret"

    def test_valid_data_without_password_for_anonymous_user(self):
        request = self.factory.post("/shortener/create/", {"url": self.valid_url})
        request.user = AnonymousUser()

        serializer = ShortenerSerializer(
            data={"url": self.valid_url}, context={"request": request}
        )
        self.assertTrue(serializer.is_valid())

    def test_set_password_requires_authenticated_user(self):
        request = self.factory.post(
            "/shortener/create/",
            {"url": self.valid_url, "password": self.test_password},
        )
        request.user = AnonymousUser()

        serializer = ShortenerSerializer(
            data={"url": self.valid_url, "password": self.test_password},
            context={"request": request},
        )
        with self.assertRaises(ValidationError):
            serializer.is_valid(raise_exception=True)

    def test_authenticated_user_can_set_password(self):
        request = self.factory.post(
            "/shortener/create/",
            {"url": self.valid_url, "password": self.test_password},
        )
        request.user = self.user

        serializer = ShortenerSerializer(
            data={"url": self.valid_url, "password": self.test_password},
            context={"request": request},
        )
        self.assertTrue(serializer.is_valid())


class ShortenerDetailSerializerTests(TestCase):
    """
    Test suite for validating the functionality of the ShortenerDetailSerializer.

    Methods:
        test_detail_serializer_fields:
            Ensures that the serialized data contains the expected fields for a Shortener instance.
    """

    def test_detail_serializer_fields(self):
        shortener = Shortener.objects.create(url="https://example.com")
        serializer = ShortenerDetailSerializer(instance=shortener)
        expected_fields = {
            "url",
            "short_code",
            "created_at",
            "expires_at",
            "views",
            "password",
            "available",
        }
        self.assertEqual(set(serializer.data.keys()), expected_fields)


class ShortenerUpdateSerializerTests(TestCase):
    """
    Unit tests for the ShortenerUpdateSerializer.

    This test case verifies the behavior of the ShortenerUpdateSerializer when
    updating a Shortener instance with partial fields.

    Methods:
        test_update_serializer_accepts_partial_fields:
            Ensures that the serializer correctly validates and accepts partial
            updates to a Shortener instance, such as updating only the 'available'
            field while leaving other fields unchanged.
    """

    def test_update_serializer_accepts_partial_fields(self):
        shortener = Shortener.objects.create(url="https://example.com")
        serializer = ShortenerUpdateSerializer(
            instance=shortener, data={"available": False}, partial=True
        )
        self.assertTrue(serializer.is_valid())
