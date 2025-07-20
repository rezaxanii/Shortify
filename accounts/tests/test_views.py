from datetime import timedelta

import redis
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import RefreshTokenBlackList, User
from utils import generate_confirmation_token


class UserRegisterViewTests(APITestCase):
    """
    Test suite for the User Registration view in the accounts app.
    This test class validates the behavior of the user registration endpoint, ensuring
    that it handles various scenarios correctly, including successful registration,
    validation errors for invalid usernames and passwords, and duplicate email errors.

    Test Cases:
    1. test_register_success:
        Verifies that a user can successfully register with valid data, and the response
        contains access and refresh tokens.
    2. test_username_starts_with_number:
        Ensures that usernames starting with a number are rejected with a 422 status code.
    3. test_username_starts_with_underscore:
        Ensures that usernames starting with an underscore are rejected with a 422 status code.
    4. test_username_contains_invalid_characters:
        Validates that usernames containing invalid characters (e.g., "$") are rejected.
    5. test_password_missing_uppercase:
        Checks that passwords missing an uppercase letter are rejected with a 422 status code.
    6. test_password_missing_lowercase:
        Checks that passwords missing a lowercase letter are rejected with a 422 status code.
    7. test_password_missing_digit_or_symbol:
        Ensures that passwords missing a digit or special symbol are rejected.
    8. test_duplicate_email_returns_error:
        Verifies that attempting to register with an email already in use results in a 422 status code.
    """

    def setUp(self):
        self.url = reverse("accounts:register")
        self.valid_data = {
            "username": "valid_user",
            "email": "valid@example.com",
            "password": "StrongPass1!",
        }

    def test_register_success(self):
        response = self.client.post(self.url, data=self.valid_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        self.assertTrue(User.objects.filter(username="valid_user").exists())

    def test_username_starts_with_number(self):
        data = self.valid_data.copy()
        data["username"] = "1invalid"
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn("username", response.data)

    def test_username_starts_with_underscore(self):
        data = self.valid_data.copy()
        data["username"] = "_invalid"
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn("username", response.data)

    def test_username_contains_invalid_characters(self):
        data = self.valid_data.copy()
        data["username"] = "invalid$user"
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn("username", response.data)

    def test_password_missing_uppercase(self):
        data = self.valid_data.copy()
        data["password"] = "weakpass1!"
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn("password", response.data)

    def test_password_missing_lowercase(self):
        data = self.valid_data.copy()
        data["password"] = "WEAKPASS1!"
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn("password", response.data)

    def test_password_missing_digit_or_symbol(self):
        data = self.valid_data.copy()
        data["password"] = "OnlyLetters"
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn("password", response.data)

    def test_duplicate_email_returns_error(self):
        User.objects.create_user(**self.valid_data)
        data = self.valid_data.copy()
        data["username"] = "another_user"
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn("email", response.data)


class UserLoginViewTests(APITestCase):
    """
    Test suite for the User Login View.
    This test class contains unit tests to verify the behavior of the login endpoint
    in the accounts application. It ensures that the login functionality works as expected
    under various conditions.

    Tests:
    - `test_login_successful_returns_tokens`: Verifies that a successful login returns
        access and refresh tokens.
    - `test_login_fails_with_wrong_password`: Ensures that login fails when an incorrect
        password is provided.
    - `test_login_fails_with_nonexistent_user`: Checks that login fails when attempting
        to authenticate a nonexistent user.
    - `test_login_fails_if_user_is_inactive`: Confirms that login fails if the user account
        is inactive.
    - `test_login_fails_with_invalid_data`: Validates that login fails when required data
        (e.g., password) is missing or invalid.
    """

    def setUp(self):
        self.url = reverse("accounts:login")
        self.user = User.objects.create_user(
            username="testuser",
            email="testuser@example.com",
            password="StrongPass1!",
        )

        self.user.is_active = True
        self.user.save()

        self.valid_data = {"username": "testuser", "password": "StrongPass1!"}

    def test_login_successful_returns_tokens(self):
        response = self.client.post(self.url, data=self.valid_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_login_fails_with_wrong_password(self):
        data = self.valid_data.copy()
        data["password"] = "WrongPassword123"
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)

    def test_login_fails_with_nonexistent_user(self):
        data = {"username": "unknownuser", "password": "SomePassword123"}
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)

    def test_login_fails_if_user_is_inactive(self):
        self.user.is_active = False
        self.user.save()

        response = self.client.post(self.url, data=self.valid_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)

    def test_login_fails_with_invalid_data(self):
        data = {"username": "testuser"}
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)


class ConfirmEmailViewTests(APITestCase):
    """
    Test suite for the ConfirmEmailView in the accounts application.
    This test class contains unit tests to verify the behavior of the email confirmation view.
    It ensures that the email confirmation process works correctly under various scenarios.

    Tests:
    - test_confirm_email_success_for_inactive_user:
        Verifies that an inactive user becomes active after successfully confirming their email.
    - test_confirm_email_for_already_active_user:
        Ensures that the email confirmation view handles already active users gracefully.
    - test_confirm_email_invalid_token:
        Tests the behavior of the view when an invalid token is provided.
    - test_confirm_email_user_does_not_exist:
        Checks the response when the user associated with the token no longer exists.

    Setup:
    - Creates a test user with a valid email and generates a confirmation token.
    - Constructs the URL for the email confirmation view using the generated token.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser", email="testuser@example.com", password="StrongPass1!"
        )
        self.token = generate_confirmation_token(
            self.user.email, salt=settings.ITD_EMAIL_CONFIRM_SALT
        )
        self.url = reverse("accounts:confirm_email", kwargs={"token": self.token})

    def test_confirm_email_success_for_inactive_user(self):
        self.assertFalse(self.user.is_active)

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTemplateUsed(response, "email_confirm.html")

        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)

    def test_confirm_email_for_already_active_user(self):
        self.user.is_active = True
        self.user.save()

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTemplateUsed(response, "email_confirm.html")

    def test_confirm_email_invalid_token(self):
        invalid_token = "this.is.invalid.token"
        url = reverse("accounts:confirm_email", kwargs={"token": invalid_token})

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTemplateUsed(response, "email_confirm_failed.html")

    def test_confirm_email_user_does_not_exist(self):
        self.user.delete()

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTemplateUsed(response, "email_confirm_failed.html")


class UserUpdateViewTests(APITestCase):
    """
    Test suite for the UserUpdateView in the accounts application.
    This test class contains unit tests to verify the functionality of updating a user's username
    via the UserUpdateView endpoint. It uses Django REST Framework's APITestCase for testing.

    Methods:
        setUp():
            Sets up the test environment by creating a test user, generating an access token,
            and defining the URL for the update endpoint.
        test_update_username_success():
            Tests that a user can successfully update their username when authenticated
            and providing valid data.
        test_update_username_unauthenticated():
            Tests that an unauthenticated user cannot update their username and receives
            a 401 Unauthorized response.
        test_update_username_invalid_format():
            Tests that attempting to update the username with an invalid format results
            in a 400 Bad Request response and includes an error message for the username field.
        test_update_username_already_exists():
            Tests that attempting to update the username to one that already exists results
            in a 400 Bad Request response and includes an error message for the username field.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser", email="testuser@example.com", password="StrongPass1!"
        )
        self.user.is_active = True
        self.user.save()

        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)

        self.url = reverse("accounts:update")

    def test_update_username_success(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        data = {"username": "newusername"}

        response = self.client.patch(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, "newusername")

    def test_update_username_unauthenticated(self):
        data = {"username": "newusername"}
        response = self.client.patch(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_username_invalid_format(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        data = {"username": "Invalid Username!"}

        response = self.client.patch(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("username", response.data)

    def test_update_username_already_exists(self):
        User.objects.create_user(
            username="existinguser",
            email="existing@example.com",
            password="StrongPass1!",
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        data = {"username": "existinguser"}

        response = self.client.patch(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("username", response.data)


class UserLogoutViewTests(APITestCase):
    """
    Test suite for the UserLogoutView API endpoint.
    This test class contains unit tests to verify the functionality of the logout endpoint,
    ensuring that users can log out successfully and that appropriate error responses are
    returned for invalid or missing tokens.

    Tests:
    - `test_logout_success`: Verifies that a user can log out successfully, and the access
        token is invalidated in Redis while the refresh token is blacklisted.
    - `test_logout_fails_without_tokens`: Ensures that the logout endpoint returns a 400
        status code when access and refresh tokens are not provided.
    - `test_logout_fails_unauthenticated`: Checks that an unauthenticated request to the
        logout endpoint returns a 401 status code.
    - `test_logout_fails_with_invalid_token`: Confirms that the logout endpoint returns a
        400 status code when invalid access and refresh tokens are provided.

    Setup:
    - Creates a test user with valid credentials and generates access and refresh tokens.
    - Configures Redis instance for token validation.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="logout_user", email="logout@example.com", password="StrongPass1!"
        )
        self.user.is_active = True
        self.user.save()

        self.refresh = RefreshToken.for_user(self.user)
        self.access_token = str(self.refresh.access_token)
        self.refresh_token = str(self.refresh)

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        self.url = reverse("accounts:logout")

        self.redis_instance = redis.Redis.from_url(
            settings.CACHES["default"]["LOCATION"]
        )

    def test_logout_success(self):
        data = {"access": self.access_token, "refresh": self.refresh_token}

        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "Successfully logged out.")
        self.assertTrue(
            RefreshTokenBlackList.objects.filter(token=self.refresh_token).exists()
        )
        self.assertTrue(self.redis_instance.exists(self.access_token))

    def test_logout_fails_without_tokens(self):
        response = self.client.post(self.url, data={})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Access and refresh tokens are required.", str(response.data))

    def test_logout_fails_unauthenticated(self):
        self.client.credentials()
        data = {"access": self.access_token, "refresh": self.refresh_token}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_fails_with_invalid_token(self):
        data = {"access": "invalid_access_token", "refresh": "invalid_refresh_token"}

        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("detail", response.data)


class UserDeleteViewTests(APITestCase):
    """
    Test suite for the UserDeleteView in the accounts application.
    This test class verifies the functionality of the user account deletion endpoint.
    It includes tests for authenticated and unauthenticated users attempting to delete an account.

    Methods:
        setUp():
            Sets up the test environment by creating a test user, generating an access token,
            and configuring the client with authentication credentials.
        test_user_can_delete_account():
            Tests that an authenticated user can successfully delete their account.
            Verifies the response status code, success message, and that the user is removed from the database.
        test_unauthenticated_user_cannot_delete():
            Tests that an unauthenticated user cannot delete an account.
            Verifies the response status code indicating unauthorized access.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="deleteuser",
            email="deleteuser@example.com",
            password="StrongPass1!",
        )
        self.user.is_active = True
        self.user.save()

        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
        self.url = reverse("accounts:delete")

    def test_user_can_delete_account(self):
        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "Account deleted successfully.")
        self.assertFalse(User.objects.filter(username="deleteuser").exists())

    def test_unauthenticated_user_cannot_delete(self):
        self.client.credentials()
        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TokenRefreshViewTests(APITestCase):
    """
    Unit tests for the Token Refresh View in the accounts application.
    This test suite verifies the functionality of the token refresh endpoint, ensuring
    that valid refresh tokens generate new access tokens, blocked refresh tokens are
    rejected, and missing refresh tokens result in appropriate error responses.

    Classes:
        TokenRefreshViewTests: Contains test cases for the token refresh functionality.

    Methods:
        setUp():
            Sets up the test environment by creating a user, generating a refresh token,
            and defining the URL for the token refresh endpoint.
        test_refresh_token_successful():
            Tests that a valid refresh token successfully generates a new access token.
        test_refresh_token_blocked():
            Tests that a blocked refresh token is rejected with an appropriate error response.
        test_refresh_token_missing():
            Tests that a missing refresh token results in a 400 Bad Request response.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="refreshuser", email="refresh@example.com", password="StrongPass1!"
        )
        self.user.is_active = True
        self.user.save()

        self.refresh = RefreshToken.for_user(self.user)
        self.refresh_token = str(self.refresh)
        self.url = reverse("accounts:token_refresh")

    def test_refresh_token_successful(self):
        response = self.client.post(self.url, {"refresh": self.refresh_token})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)

    def test_refresh_token_blocked(self):
        RefreshTokenBlackList.objects.create(
            user=self.user,
            token=self.refresh_token,
            expires_at=timezone.now() + timedelta(days=1),
        )

        response = self.client.post(self.url, {"refresh": self.refresh_token})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid Token", response.data["detail"])

    def test_refresh_token_missing(self):
        response = self.client.post(self.url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class EmailChangeViewTests(APITestCase):
    """
    Test suite for the EmailChangeView in the accounts application.
    This test class uses Django's APITestCase to verify the functionality of the email change endpoint.
    It includes tests for successful email change, handling duplicate emails, authentication requirements,
    and validation of email format.

    Tests:
    - test_change_email_successfully: Verifies that a user can successfully change their email address.
    - test_change_email_fails_if_email_already_exists: Ensures the endpoint returns an error if the new email is already in use.
    - test_change_email_requires_authentication: Confirms that authentication is required to access the email change endpoint.
    - test_change_email_fails_with_invalid_email_format: Checks that the endpoint validates the format of the provided email address.

    Setup:
    - Creates a test user with an active account and generates an access token for authentication.
    - Configures the test client with the access token for authenticated requests.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="emailchanger", email="old@example.com", password="StrongPass1!"
        )
        self.user.is_active = True
        self.user.save()

        self.url = reverse("accounts:change_email")
        self.refresh = RefreshToken.for_user(self.user)
        self.access_token = str(self.refresh.access_token)

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access_token}")

    def test_change_email_successfully(self):
        new_email = "new@example.com"
        response = self.client.post(self.url, {"new_email": new_email})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("message", response.data)

        self.user.refresh_from_db()
        self.assertEqual(self.user.new_email, new_email)

    def test_change_email_fails_if_email_already_exists(self):
        User.objects.create_user(
            username="otheruser",
            email="duplicate@example.com",
            password="AnotherPass1!",
        )

        response = self.client.post(self.url, {"new_email": "duplicate@example.com"})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("This email already in use", str(response.data))

    def test_change_email_requires_authentication(self):
        self.client.credentials()
        response = self.client.post(self.url, {"new_email": "noauth@example.com"})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_change_email_fails_with_invalid_email_format(self):
        response = self.client.post(self.url, {"new_email": "notanemail"})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Enter a valid email address", str(response.data))


class EmailChangeConfirmViewTests(APITestCase):
    """
    Tests for the EmailChangeConfirmView.
    This test suite verifies the functionality of the email change confirmation view,
    including successful email change, handling of invalid tokens, and scenarios where
    the user does not exist.

    Classes:
        EmailChangeConfirmViewTests: Contains test cases for the email change confirmation view.

    Methods:
        setUp():
            Sets up the test environment by creating a user, generating a confirmation token,
            and defining the URL for the email change confirmation view.
        test_confirm_change_email_successfully():
            Tests that the email change confirmation succeeds when provided with a valid token.
            Verifies the response status code, template used, and updates to the user's email.
        test_confirm_change_email_invalid_token():
            Tests that the email change confirmation fails when provided with an invalid token.
            Verifies the response status code and template used.
        test_confirm_change_email_user_not_found():
            Tests that the email change confirmation fails when the user does not exist.
            Verifies the response status code and template used.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="changeconfirm", email="old@example.com", password="StrongPass1!"
        )
        self.user.new_email = "new@example.com"
        self.user.is_active = True
        self.user.save()

        self.token = generate_confirmation_token(
            self.user.new_email, salt=settings.ITD_EMAIL_CHANGE_SALT
        )
        self.url = reverse("accounts:confirm_change_email", args=[self.token])

    def test_confirm_change_email_successfully(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "email_change_success.html")

        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "new@example.com")
        self.assertIsNone(self.user.new_email)

    def test_confirm_change_email_invalid_token(self):
        url = reverse("accounts:confirm_change_email", args=["invalidtoken"])
        response = self.client.get(url)

        self.assertEqual(response.status_code, 400)
        self.assertTemplateUsed(response, "email_change_failed.html")

    def test_confirm_change_email_user_not_found(self):
        self.user.delete()
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 404)
        self.assertTemplateUsed(response, "email_change_failed.html")


class PasswordChangeViewTests(APITestCase):
    """
    Test suite for the Password Change View in the accounts application.
    This test class verifies the functionality of sending password change links
    via email. It includes tests for successful requests, handling of invalid
    email formats, nonexistent emails, and empty email fields.

    Tests:
    - `test_send_password_change_link_success`: Ensures a password change link is
        successfully sent when a valid email is provided.
    - `test_send_password_change_with_nonexistent_email`: Verifies that the view
        returns an error when the provided email does not exist in the system.
    - `test_send_password_change_with_invalid_email_format`: Checks that the view
        handles invalid email formats correctly and returns appropriate error messages.
    - `test_send_password_change_with_empty_email`: Ensures the view returns an
        error when the email field is left blank.
    """

    def setUp(self):
        self.url = reverse("accounts:change_password")
        self.user_email = "user@example.com"
        self.user_password = "Password123!"
        self.user = User.objects.create_user(
            username="testuser",
            email=self.user_email,
            password=self.user_password,
        )
        self.user.is_active = True

    def test_send_password_change_link_success(self):
        response = self.client.post(self.url, {"email": self.user_email})
        self.assertEqual(response.status_code, 200)
        self.assertIn("message", response.data)
        self.assertIn("Password change link has been sent", response.data["message"])

    def test_send_password_change_with_nonexistent_email(self):
        response = self.client.post(self.url, {"email": "notfound@example.com"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("errors", response.data)
        self.assertIn("email", response.data["errors"])
        self.assertIn("not found", str(response.data["errors"]["email"][0]))

    def test_send_password_change_with_invalid_email_format(self):
        response = self.client.post(self.url, {"email": "invalid-email"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("errors", response.data)
        self.assertIn("email", response.data["errors"])
        self.assertIn("valid email", str(response.data["errors"]["email"][0]).lower())

    def test_send_password_change_with_empty_email(self):
        response = self.client.post(self.url, {"email": ""})
        self.assertEqual(response.status_code, 400)
        self.assertIn("errors", response.data)
        self.assertIn("email", response.data["errors"])
        self.assertIn(
            "may not be blank", str(response.data["errors"]["email"][0]).lower()
        )


class PasswordChangeConfirmViewTests(APITestCase):
    """
    Tests for the PasswordChangeConfirmView.
    This test suite verifies the behavior of the password change confirmation view,
    which handles both GET and POST requests for confirming password changes.

    Test Cases:
    - test_get_request_with_valid_token_displays_form:
        Ensures that a GET request with a valid token displays the password change form.
    - test_get_request_with_invalid_token_shows_error_page:
        Ensures that a GET request with an invalid token shows an error page.
    - test_post_with_valid_token_and_valid_password_changes_password:
        Ensures that a POST request with a valid token and valid password updates the user's password
        and displays a success page.
    - test_post_with_valid_token_and_invalid_form_shows_form_again:
        Ensures that a POST request with a valid token but invalid form data redisplays the form
        with an appropriate error.
    - test_post_with_invalid_token_shows_error_page:
        Ensures that a POST request with an invalid token shows an error page.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="passconfirmer",
            email="passconfirm@example.com",
            password="OldPass123!",
        )
        self.token = generate_confirmation_token(
            self.user.email, salt=settings.ITD_RESET_PASSWORD_SALT
        )
        self.url = reverse("accounts:confirm_change_password", args=[self.token])

    def test_get_request_with_valid_token_displays_form(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "password_change.html")

    def test_get_request_with_invalid_token_shows_error_page(self):
        url = reverse("accounts:confirm_change_password", args=["invalidtoken"])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)
        self.assertTemplateUsed(response, "password_change_failed.html")

    def test_post_with_valid_token_and_valid_password_changes_password(self):
        new_password = "NewStrongPass1!"
        response = self.client.post(
            self.url, {"password": new_password, "confirm_password": new_password}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "password_change_success.html")

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))

    def test_post_with_valid_token_and_invalid_form_shows_form_again(self):
        response = self.client.post(self.url, {"password": ""})

        self.assertEqual(response.status_code, 400)
        self.assertTemplateUsed(response, "password_change.html")

    def test_post_with_invalid_token_shows_error_page(self):
        url = reverse("accounts:confirm_change_password", args=["invalidtoken"])
        response = self.client.post(url, {"password": "SomePass1!"})

        self.assertEqual(response.status_code, 404)
        self.assertTemplateUsed(response, "password_change_failed.html")
