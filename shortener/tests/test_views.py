import datetime

from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from shortener.models import Shortener

User = get_user_model()


class ShortenerViewTests(APITestCase):
    """
    Test suite for the Shortener views.
    This test class contains unit tests for the Shortener app's views, ensuring
    that the URL shortening functionality behaves as expected for both authenticated
    and unauthenticated users.

    Classes:
        ShortenerViewTests: Test cases for the Shortener views.

    Methods:
        setUp():
            Sets up the test environment by creating a test user and initializing
            the API client and URL for the create_url endpoint.
        test_create_short_url_unauthenticated():
            Tests that an unauthenticated user can create a short URL and that the
            resulting Shortener object does not associate a user.
        test_create_short_url_authenticated():
            Tests that an authenticated user can create a short URL and that the
            resulting Shortener object is associated with the authenticated user.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="test_user", email="user@example.com", password="password123"
        )
        self.client = APIClient()
        self.create_url = reverse("shortener:create_url")

    def test_create_short_url_unauthenticated(self):
        data = {"url": "https://example.com"}
        response = self.client.post(self.create_url, data)
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(Shortener.objects.first().user)

    def test_create_short_url_authenticated(self):
        self.client.force_authenticate(user=self.user)
        data = {"url": "https://example.com"}
        response = self.client.post(self.create_url, data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Shortener.objects.first().user, self.user)


class ShortenerListViewTests(APITestCase):
    """
    Tests for the ShortenerListView API endpoint.
    This test case verifies the behavior of the ShortenerListView, ensuring that
    only URLs belonging to the authenticated user are returned.
    Classes:
        ShortenerListViewTests: Contains setup and test methods for the ShortenerListView.
    Methods:
        setUp:
            Sets up test data including users, shortener URLs, and authentication.
        test_list_only_authenticated_user_urls:
            Tests that the API endpoint returns only the URLs associated with the authenticated user.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="user1", email="user1@example.com", password="pass"
        )
        self.other_user = User.objects.create_user(
            username="user2", email="user2@example.com", password="pass"
        )
        self.shortener1 = Shortener.objects.create(
            user=self.user, url="https://one.com"
        )
        self.shortener2 = Shortener.objects.create(
            user=self.other_user, url="https://two.com"
        )
        self.client.force_authenticate(user=self.user)
        self.list_url = reverse("shortener:list_urls")

    def test_list_only_authenticated_user_urls(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["url"], "https://one.com")


class ShortenerDetailViewTests(APITestCase):
    """
    Tests for the ShortenerDetailView API endpoint.
    This test case verifies the behavior of the detail view for the Shortener model,
    ensuring that users can access their own shortened URLs but are restricted from
    accessing URLs belonging to other users.

    Test Cases:
    - test_get_detail_own_url: Ensures that a user can retrieve details of their own
        shortened URL successfully.
    - test_get_detail_other_user_denied: Ensures that a user cannot access the details
        of a shortened URL belonging to another user, returning a 404 status code.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="user1", email="u1@example.com", password="pass"
        )
        self.other_user = User.objects.create_user(
            username="user2", email="u2@example.com", password="pass"
        )
        self.obj = Shortener.objects.create(user=self.user, url="https://example.com")
        self.client.force_authenticate(user=self.user)
        self.url = reverse("shortener:detail_url", args=[self.obj.pk])

    def test_get_detail_own_url(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["url"], "https://example.com")

    def test_get_detail_other_user_denied(self):
        self.client.force_authenticate(user=self.other_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 404)


class ShortenerUpdateViewTests(APITestCase):
    """
    Tests for the ShortenerUpdateView.
    This test suite verifies the behavior of the update functionality for the Shortener model.
    It includes tests for successfully updating a URL and ensuring that users cannot update
    URLs belonging to other users.

    Classes:
        ShortenerUpdateViewTests: Test cases for the Shortener update view.

    Methods:
        setUp():
            Sets up test data including users, a Shortener object, and authentication.
        test_update_url_successfully():
            Tests that a user can successfully update their own Shortener URL.
        test_update_other_user_denied():
            Tests that a user cannot update a Shortener URL belonging to another user.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser", email="t@example.com", password="pass"
        )
        self.other_user = User.objects.create_user(
            username="other", email="o@example.com", password="pass"
        )
        self.obj = Shortener.objects.create(user=self.user, url="https://before.com")
        self.client.force_authenticate(user=self.user)
        self.url = reverse("shortener:update_url", args=[self.obj.pk])

    def test_update_url_successfully(self):
        response = self.client.patch(
            self.url, {"url": "https://after.com"}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        self.obj.refresh_from_db()
        self.assertEqual(self.obj.url, "https://after.com")

    def test_update_other_user_denied(self):
        self.client.force_authenticate(user=self.other_user)
        response = self.client.patch(self.url, {"url": "https://hack.com"})
        self.assertEqual(response.status_code, 403)


class ShortenerDeleteViewTests(APITestCase):
    """
    Tests for the ShortenerDeleteView.
    This test suite verifies the behavior of the delete functionality for the Shortener model.

    Classes:
        ShortenerDeleteViewTests: Contains tests for deleting Shortener objects.

    Methods:
        setUp():
            Sets up the test environment by creating test users, a Shortener object, and authenticating the client.
        test_delete_successfully():
            Tests that a Shortener object can be successfully deleted by its owner, returning a 204 status code.
        test_delete_other_user_denied():
            Tests that a user cannot delete a Shortener object owned by another user, returning a 403 status code.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="u", email="u@example.com", password="pass"
        )
        self.other_user = User.objects.create_user(
            username="o", email="o@example.com", password="pass"
        )
        self.obj = Shortener.objects.create(user=self.user, url="https://delete.com")
        self.client.force_authenticate(user=self.user)
        self.url = reverse("shortener:delete_url", args=[self.obj.pk])

    def test_delete_successfully(self):
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Shortener.objects.filter(pk=self.obj.pk).exists())

    def test_delete_other_user_denied(self):
        self.client.force_authenticate(user=self.other_user)
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, 403)


class RedirectShortURLViewTests(APITestCase):
    """
    Test suite for the RedirectShortURLView in the Shortify application.
    This test class contains unit tests to verify the behavior of the URL redirection
    view, including handling valid and expired URLs, as well as password-protected URLs.

    Tests:
    - `test_redirect_valid_url`: Ensures that a valid short URL redirects to the target URL with a 302 status code.
    - `test_redirect_expired_url`: Verifies that an expired short URL returns a 410 status code.
    - `test_redirect_with_password_success`: Checks that a password-protected URL redirects successfully when the correct password is provided.
    - `test_redirect_with_wrong_password`: Ensures that providing an incorrect password results in a 401 status code.
    - `test_redirect_missing_password`: Confirms that attempting to access a password-protected URL without providing a password results in a 401 status code.
    """

    def setUp(self):
        self.url_obj = Shortener.objects.create(
            url="https://target.com", short_code="abcd", available=True
        )

    def test_redirect_valid_url(self):
        url = reverse("shortener:redirect_url", args=["abcd"])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "https://target.com")

    def test_redirect_expired_url(self):
        self.url_obj.expires_at = timezone.now() - datetime.timedelta(days=1)
        self.url_obj.save()
        url = reverse("shortener:redirect_url", args=["abcd"])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 410)

    def test_redirect_with_password_success(self):
        self.url_obj.password = "1234"
        self.url_obj.save()
        url = reverse("shortener:redirect_url", args=["abcd"]) + "?password=1234"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)

    def test_redirect_with_wrong_password(self):
        self.url_obj.password = "1234"
        self.url_obj.save()
        url = reverse("shortener:redirect_url", args=["abcd"]) + "?password=wrong"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 401)

    def test_redirect_missing_password(self):
        self.url_obj.password = "1234"
        self.url_obj.save()
        url = reverse("shortener:redirect_url", args=["abcd"])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 401)
