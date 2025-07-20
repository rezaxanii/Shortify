from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from accounts.models import User
from shortener.models import Shortener


class ShortenerModelTests(TestCase):
    """
    Unit tests for the Shortener model.

    This test suite includes the following tests:
    - `test_create_shortener_for_authenticated_user_sets_30_days_expiry`: Verifies that a shortener created for an authenticated user has an expiry date set to 30 days from creation.
    - `test_create_shortener_for_anonymous_user_sets_12_hours_expiry`: Ensures that a shortener created for an anonymous user has an expiry date set to 12 hours from creation.
    - `test_is_expired_returns_true_for_expired_link`: Checks that the `is_expired` method returns `True` for a shortener whose expiry date has passed.
    - `test_is_expired_returns_false_for_active_link`: Confirms that the `is_expired` method returns `False` for a shortener whose expiry date is still in the future.
    - `test_str_representation`: Tests the string representation of the Shortener model, ensuring it includes the URL and short code.

    Setup:
    - Creates a test user for use in tests involving authenticated users.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="test_user", password="test_pass", email="test@example.com"
        )

    def test_create_shortener_for_authenticated_user_sets_30_days_expiry(self):
        shortener = Shortener.objects.create(user=self.user, url="https://example.com")
        expected_expiry = timezone.now() + timedelta(days=30)
        self.assertAlmostEqual(
            shortener.expires_at.timestamp(), expected_expiry.timestamp(), delta=10
        )
        self.assertEqual(shortener.user, self.user)
        self.assertTrue(shortener.short_code)

    def test_create_shortener_for_anonymous_user_sets_12_hours_expiry(self):
        shortener = Shortener.objects.create(user=None, url="https://example.com")
        expected_expiry = timezone.now() + timedelta(hours=12)
        self.assertAlmostEqual(
            shortener.expires_at.timestamp(), expected_expiry.timestamp(), delta=10
        )
        self.assertIsNone(shortener.user)
        self.assertTrue(shortener.short_code)

    def test_is_expired_returns_true_for_expired_link(self):
        expired_time = timezone.now() - timedelta(hours=1)
        shortener = Shortener.objects.create(user=self.user, url="https://example.com")
        shortener.expires_at = expired_time
        shortener.save()
        self.assertTrue(shortener.is_expired())

    def test_is_expired_returns_false_for_active_link(self):
        future_time = timezone.now() + timedelta(hours=1)
        shortener = Shortener.objects.create(user=self.user, url="https://example.com")
        shortener.expires_at = future_time
        shortener.save()
        self.assertFalse(shortener.is_expired())

    def test_str_representation(self):
        shortener = Shortener.objects.create(user=self.user, url="https://example.com")
        self.assertIn(shortener.url, str(shortener))
        self.assertIn(shortener.short_code, str(shortener))
