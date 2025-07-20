from django.contrib.auth.models import BaseUserManager


class UserManager(BaseUserManager):
    """
    Custom manager for User model providing methods to create regular users and superusers.

    Methods:
    create_user(username, email, password)
        Creates and returns a user with the given username, email, and password.
        Raises ValueError if any required field is missing.

    create_superuser(username, email, password)
        Creates and returns a superuser with the given username, email, and password.
        Sets is_admin, is_superuser, and is_active flags to True.
    """

    def create_user(self, username, email, password):
        if not username:
            raise ValueError("username is required")
        if not email:
            raise ValueError("email is required")
        if not password:
            raise ValueError("password is required")

        user = self.model(username=username, email=self.normalize_email(email))
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password):
        user = self.create_user(username=username, email=email, password=password)
        user.is_admin = True
        user.is_superuser = True
        user.is_active = True
        user.save(using=self._db)
        return user
