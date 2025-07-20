from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    Custom admin configuration for the User model.

    Attributes:
        list_display (tuple): Fields to display in the user list view.
        list_filter (tuple): Fields to filter users by in the admin.
        fieldsets (tuple): Field groupings for the user detail/edit view.
        search_fields (tuple): Fields to enable search functionality.
        ordering (tuple): Default ordering for user list view.
        readonly_fields (list): Fields that are read-only in the admin.
        filter_horizontal (tuple): Fields with horizontal filter widget.

    This class customizes the Django admin interface for managing users,
    including display options, permissions, and search capabilities.
    """

    list_display = ("username", "email", "is_admin", "is_active")
    list_filter = ("is_admin", "is_active")

    fieldsets = (
        (None, {"fields": ("username", "email", "password")}),
        (
            "Permissions",
            {
                "fields": (
                    "is_admin",
                    "is_active",
                    "is_superuser",
                    "created",
                    "last_login",
                    "groups",
                    "user_permissions",
                )
            },
        ),
    )

    search_fields = ("username", "email")
    ordering = ("created",)
    readonly_fields = ["created", "last_login"]
    filter_horizontal = ("groups", "user_permissions")
