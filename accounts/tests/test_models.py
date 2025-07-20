from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import TestCase

from accounts.models import RefreshTokenBlackList, User


class UserModelTest(TestCase):
    """
    Test suite for the User model.

    This test case includes the following tests:
    1. `test_can_create_active_user`: Verifies that an active user can be created with the specified attributes.
    2. `test_username_must_be_at_least_4_chars`: Ensures that a ValidationError is raised if the username is shorter than 4 characters.
    3. `test_email_must_be_unique`: Confirms that the email field must be unique, raising an IntegrityError for duplicate emails.
    4. `test_user_str_method_returns_username`: Tests that the `__str__` method of the User model returns the username.
    5. `test_is_staff_reflects_is_admin`: Checks that the `is_staff` property correctly reflects the value of the `is_admin` attribute.
    """

    def test_can_create_active_user(self):
        active_user = User.objects.create(
            username="active_user",
            email="active_user@example.com",
            password="securepassword123",
            is_active=True,
            is_admin=False,
        )

        self.assertEqual(active_user.username, "active_user")
        self.assertTrue(active_user.is_active)
        self.assertFalse(active_user.is_admin)

    def test_username_must_be_at_least_4_chars(self):
        short_username_user = User(
            username="abc", email="shortuser@example.com", password="somepassword"
        )

        with self.assertRaises(ValidationError):
            short_username_user.full_clean()

    def test_email_must_be_unique(self):
        primary_user = User.objects.create(
            username="primary_user",
            email="duplicate@example.com",
            password="password123",
        )
        with self.assertRaises(IntegrityError):
            User.objects.create(
                username="secondary_user",
                email="duplicate@example.com",
                password="anotherpassword",
            )

    def test_user_str_method_returns_username(self):
        test_user = User(username="str_user")
        self.assertEqual(str(test_user), "str_user")

    def test_is_staff_reflects_is_admin(self):
        admin_user = User(is_admin=True)
        regular_user = User(is_admin=False)
        self.assertTrue(admin_user.is_staff)
        self.assertFalse(regular_user.is_staff)


class RefreshTokenBlackListModelTest(TestCase):
    """
    Unit tests for the RefreshTokenBlackList model.
    This test case verifies the creation and string representation of
    RefreshTokenBlackList instances, as well as the association between
    the token and its user.

    Methods:
        test_token_blacklist_creation_and_str:
            Tests the creation of a RefreshTokenBlackList instance, its
            string representation, and the correctness of the user-token
            association.
    """

    def test_token_blacklist_creation_and_str(self):
        user_with_token = User.objects.create(
            username="token_user",
            email="tokenuser@example.com",
            password="pass123",
            is_active=True,
        )

        token = RefreshTokenBlackList.objects.create(
            user=user_with_token,
            token="abcde12345token",
            expires_at="2030-01-01T00:00:00Z",
        )

        self.assertEqual(str(token), f"token_user - abcde12345token")
        self.assertEqual(token.user.username, "token_user")
