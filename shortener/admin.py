from django.contrib import admin

from .models import Shortener


class ShortenerAdmin(admin.ModelAdmin):
    """
    ShortenerAdmin is a custom admin configuration for the Shortener model in the Django admin interface.

    Attributes:
        list_display (tuple): Specifies the fields to display in the admin list view.
        search_fields (tuple): Defines the fields that can be searched in the admin interface.
        list_filter (tuple): Specifies the fields to filter by in the admin list view.
        readonly_fields (tuple): Lists the fields that are read-only in the admin form.
        ordering (tuple): Defines the default ordering of records in the admin list view.
    """

    list_display = (
        "id",
        "user",
        "url",
        "short_code",
        "created_at",
        "expires_at",
        "views",
    )
    search_fields = ("url", "short_code")
    list_filter = ("created_at",)
    readonly_fields = ("short_code", "password", "created_at", "views")
    ordering = ("-created_at",)


admin.site.register(Shortener, ShortenerAdmin)
