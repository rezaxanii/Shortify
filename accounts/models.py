from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.core.validators import MinLengthValidator
from django.db import models

from .managers import UserManager


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model for authentication and user management.

    Attributes:
        username (CharField): Unique username, 4-32 characters.
        email (EmailField): Unique email address, minimum 10 characters.
        new_email (EmailField): Optional new email address, minimum 10 characters.
        password (CharField): Hashed password, up to 128 characters.
        is_active (BooleanField): Indicates if the user account is active.
        is_admin (BooleanField): Indicates if the user has admin privileges.
        created (DateTimeField): Timestamp of user creation.
        last_login (DateTimeField): Timestamp of last login.

    Manager:
        objects (UserManager): Custom manager for user creation and management.

    Meta:
        USERNAME_FIELD (str): Field used for authentication ('username').
        REQUIRED_FIELDS (list): Fields required for user creation (['email']).

    Methods:
        __str__(): Returns the username as string representation.
        is_staff: Property indicating if the user is staff (admin).
    """

    username = models.CharField(
        max_length=32, unique=True, validators=[MinLengthValidator(4)]
    )
    email = models.EmailField(
        max_length=254, unique=True, validators=[MinLengthValidator(10)]
    )
    new_email = models.EmailField(
        max_length=254, null=True, blank=True, validators=[MinLengthValidator(10)]
    )
    password = models.CharField(max_length=128)
    is_active = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)

    objects = UserManager()
    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email"]

    def __str__(self) -> str:
        return self.username

    @property
    def is_staff(self) -> bool:
        return self.is_admin


class RefreshTokenBlackList(models.Model):
    """
    Model representing a blacklist for refresh tokens.

    Attributes:
        user (ForeignKey): A reference to the User model. Indicates the user associated with the blacklisted token.
        token (CharField): The refresh token that is blacklisted. Must be unique and has a maximum length of 255 characters.
        expires_at (DateTimeField): The timestamp indicating when the blacklisted token expires.

    Methods:
        __str__(): Returns a string representation of the model instance, displaying the username and the first 20 characters of the token.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    expires_at = models.DateTimeField()

    def __str__(self) -> str:
        return f"{self.user.username} - {self.token[:20]}"
