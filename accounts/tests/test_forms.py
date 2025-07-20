from django.test import TestCase

from accounts.forms import PasswordResetForm


class PasswordResetFormTests(TestCase):
    """
    Unit tests for the PasswordResetForm.
    This test suite validates the behavior of the PasswordResetForm, ensuring
    that it correctly handles various scenarios related to password validation
    and confirmation.

    Test Cases:
    - test_valid_password_and_confirmation:
        Verifies that the form is valid when the password and confirmation match
        and meet all requirements.
    - test_password_too_short:
        Ensures the form is invalid when the password is shorter than the minimum
        required length (8 characters).
    - test_password_missing_uppercase:
        Checks that the form is invalid when the password lacks an uppercase letter.
    - test_password_missing_lowercase:
        Confirms that the form is invalid when the password lacks a lowercase letter.
    - test_password_missing_digit_or_special:
        Validates that the form is invalid when the password lacks a digit or special
        character.
    - test_passwords_do_not_match:
        Ensures the form is invalid when the password and confirmation do not match.
    Each test case verifies the presence of appropriate error messages in the form
    when validation fails.
    """

    def test_valid_password_and_confirmation(self):
        form_data = {"password": "ValidPass123!", "confirm_password": "ValidPass123!"}
        form = PasswordResetForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_password_too_short(self):
        form_data = {"password": "Ab1!", "confirm_password": "Ab1!"}
        form = PasswordResetForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("password", form.errors)
        self.assertIn("at least 8 characters", str(form.errors["password"]))

    def test_password_missing_uppercase(self):
        form_data = {"password": "validpass123!", "confirm_password": "validpass123!"}
        form = PasswordResetForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("password", form.errors)
        self.assertIn("uppercase letter", str(form.errors["password"]))

    def test_password_missing_lowercase(self):
        form_data = {"password": "VALID123!", "confirm_password": "VALID123!"}
        form = PasswordResetForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("password", form.errors)
        self.assertIn("lowercase letter", str(form.errors["password"]))

    def test_password_missing_digit_or_special(self):
        form_data = {"password": "ValidPass", "confirm_password": "ValidPass"}
        form = PasswordResetForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("password", form.errors)
        self.assertIn("digit or special character", str(form.errors["password"]))

    def test_passwords_do_not_match(self):
        form_data = {"password": "ValidPass123!", "confirm_password": "Different123!"}
        form = PasswordResetForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("__all__", form.errors)
        self.assertIn("Passwords do not match", str(form.errors["__all__"]))
