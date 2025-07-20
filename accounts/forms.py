import re

from django import forms


class PasswordResetForm(forms.Form):
    """
    A Django form for resetting a user's password with validation.

    Fields:
        password (CharField): The new password input, masked for privacy.
        confirm_password (CharField): Confirmation of the new password, masked for privacy.

    Validation:
        - Password must be at least 8 characters long.
        - Password must contain at least one uppercase letter.
        - Password must contain at least one lowercase letter.
        - Password must contain at least one digit or special character (0-9@_-#!*/.,|()=+).
        - Password and confirm_password must match.

    Raises:
        forms.ValidationError: If any validation rule is violated.
    """

    password = forms.CharField(widget=forms.PasswordInput, label="New Password")
    confirm_password = forms.CharField(
        widget=forms.PasswordInput, label="Confirm Password"
    )

    def clean_password(self):
        password = self.cleaned_data.get("password")

        if len(password) < 8:
            raise forms.ValidationError("Password must be at least 8 characters long.")

        if not re.search(r"[A-Z]", password):
            raise forms.ValidationError(
                "Password must include at least one uppercase letter."
            )

        if not re.search(r"[a-z]", password):
            raise forms.ValidationError(
                "Password must include at least one lowercase letter."
            )

        if not re.search(r"[0-9@_\-#!*/.,|()=+]", password):
            raise forms.ValidationError(
                "Password must include at least one digit or special character."
            )

        return password

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")
