from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


def generate_confirmation_token(email, salt) -> str:
    """
    Generates a confirmation token for the given email using the provided salt.

    Args:
        email (str): The email address to generate the token for.
        salt (str): The salt value to use for token generation.

    Returns:
        str: A time-sensitive confirmation token as a string.
    """
    serializer = URLSafeTimedSerializer(settings.ITD_SECRET_KEY)
    return serializer.dumps(email, salt=salt)


def send_activation_email(user, request, _type, new_email=None):
    """
    Sends an activation email to the user for various account actions such as email confirmation,
    email change confirmation, or password change.
    Parameters:
        user (User): The user object to whom the email will be sent.
        request (HttpRequest): The current HTTP request object, used to build absolute URIs.
        _type (str): The type of activation email to send. Must be one of:
            - "confirm email": Sends an email confirmation link to the user's email.
            - "confirm change email": Sends a confirmation link to the new email address.
            - "change password": Sends a password change link to the user's email.
        new_email (str, optional): The new email address to confirm, required if _type is "confirm change email".
    Returns:
        None
    Side Effects:
        Sends an email to the specified recipient(s) using Django's send_mail function.
    """

    if _type == "confirm email":
        token = generate_confirmation_token(
            user.email, salt=settings.ITD_EMAIL_CONFIRM_SALT
        )
        activation_link = request.build_absolute_uri(
            reverse("accounts:confirm_email", args=[token])
        )
        subject = "Email Confirmation"
        message = (
            f"Hello {user.username}, please click the following link to confirm your email: {activation_link}\n"
            "If you did not request this, please ignore this email."
        )
        recipient_list = [user.email]

    elif _type == "confirm change email":
        token = generate_confirmation_token(
            new_email, salt=settings.ITD_EMAIL_CHANGE_SALT
        )
        activation_link = request.build_absolute_uri(
            reverse("accounts:confirm_change_email", args=[token])
        )
        subject = "Change Email"
        message = (
            f"Hello {user.username}, please click the following link to confirm your new email: {activation_link}\n"
            "If you did not request this, please ignore this email."
        )
        recipient_list = [new_email]

    elif _type == "change password":
        token = generate_confirmation_token(
            user.email, salt=settings.ITD_RESET_PASSWORD_SALT
        )
        activation_link = request.build_absolute_uri(
            reverse("accounts:confirm_change_password", args=[token])
        )
        subject = "Change Password"
        message = (
            f"Hello {user.username}, please click the following link to change your account password: {activation_link}\n"
            "If you did not request this, please ignore this email."
        )
        recipient_list = [user.email]

    email_from = settings.DEFAULT_FROM_EMAIL
    send_mail(subject, message, email_from, recipient_list)


def decode_token(token, salt):
    """
    Decodes a token to retrieve the associated email address.
    Uses a URL-safe timed serializer to validate and decode the token with the provided salt.
    Returns the email address if the token is valid and not expired (within 24 hours), otherwise returns None.
    Args:
        token (str): The token to decode.
        salt (str): The salt used for token generation and validation.
    Returns:
        str or None: The decoded email address if valid, otherwise None.
    """

    serializer = URLSafeTimedSerializer(settings.ITD_SECRET_KEY)
    try:
        email = serializer.loads(token, salt=salt, max_age=3600 * 24)
        return email
    except (SignatureExpired, BadSignature):
        return None
