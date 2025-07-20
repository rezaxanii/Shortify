from django.shortcuts import get_object_or_404, redirect
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Shortener
from .serializers import (
    ShortenerDetailSerializer,
    ShortenerSerializer,
    ShortenerUpdateSerializer,
)


class ShortenerView(generics.CreateAPIView):
    """
    API view for creating Shortener instances.

    This view allows authenticated and unauthenticated users to create new Shortener objects.
    If the user is authenticated, the created Shortener instance will be associated with the user.
    Otherwise, the user field will be set to None.

    Attributes:
        queryset (QuerySet): The queryset of Shortener objects.
        serializer_class (Serializer): The serializer class for Shortener objects.

    Methods:
        perform_create(serializer): Saves the Shortener instance, associating it with the current user if authenticated.
    """

    queryset = Shortener.objects.all()
    serializer_class = ShortenerSerializer

    def perform_create(self, serializer):
        serializer.save(
            user=self.request.user if self.request.user.is_authenticated else None
        )


class RedirectShortURLView(APIView):
    """
    APIView that handles redirection for shortened URLs.

    GET request with a short_code will:
    - Retrieve the corresponding Shortener object if available.
    - Return 410 if the link has expired.
    - If the link is password protected:
        - Return 401 if no password is provided.
        - Return 401 if an invalid password is provided.
    - Increment the view count for the link.
    - Redirect to the original URL if all checks pass.

    Args:
        request: The HTTP request object.
        short_code (str): The short code identifying the shortened URL.

    Returns:
        Response: Error response if expired or password protected.
        HttpResponseRedirect: Redirects to the original URL if valid.
    """

    def get(self, request, short_code):
        obj = get_object_or_404(Shortener, short_code=short_code, available=True)

        if obj.is_expired():
            return Response({"error": "This link has expired."}, status=410)

        password = request.query_params.get("password")
        if obj.password:
            if password is None:
                return Response(
                    {"error": "This link is password protected."}, status=401
                )
            elif not obj.password == password:
                return Response({"error": "Invalid password."}, status=401)

        obj.views += 1
        obj.save(update_fields=["views"])

        return redirect(obj.url)


class ShortenerListView(generics.ListAPIView):
    """
    API view for listing Shortener objects belonging to the authenticated user.

    - Uses `ShortenerSerializer` for serialization.
    - Supports filtering by `short_code`, `url`, `created_at`, `expires_at`, and `views`.
    - Allows searching by `short_code` and `url`.
    - Enables ordering by `created_at`, `expires_at`, and `views` (default: newest first).
    - No pagination is applied.
    - Access restricted to authenticated users only.

    The queryset is limited to Shortener objects owned by the requesting user.
    """

    serializer_class = ShortenerSerializer
    filter_fields = ["short_code", "url", "created_at", "expires_at", "views"]
    search_fields = ["short_code", "url"]
    ordering_fields = ["created_at", "expires_at", "views"]
    ordering = ["-created_at"]
    pagination_class = None
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Shortener.objects.filter(user=user)


class ShortenerDetailView(generics.RetrieveAPIView):
    """
    Retrieve a single Shortener instance belonging to the authenticated user.

    This view requires authentication and only allows access to Shortener objects
    owned by the requesting user.

    Attributes:
        permission_classes (list): List of permission classes; only authenticated users are allowed.
        queryset (QuerySet): Base queryset for Shortener objects.
        serializer_class (Serializer): Serializer for detailed Shortener representation.

    Methods:
        get_queryset(): Returns a queryset filtered to Shortener objects owned by the current user.
    """

    permission_classes = [IsAuthenticated]
    queryset = Shortener.objects.all()
    serializer_class = ShortenerDetailSerializer

    def get_queryset(self):
        return Shortener.objects.filter(user=self.request.user)


class ShortenerUpdateView(generics.UpdateAPIView):
    """
    ShortenerUpdateView is a view that handles the update operation for Shortener objects.
    It ensures that only authenticated users can access this view and restricts updates
    to objects owned by the requesting user.

    Attributes:
        permission_classes (list): Specifies the permissions required to access this view.
            Only authenticated users are allowed.
        queryset (QuerySet): Defines the set of Shortener objects that can be updated.
        serializer_class (Serializer): Specifies the serializer used for validating and
            deserializing input data.

    Methods:
        get_object():
            Retrieves the object to be updated. Ensures that the requesting user is the
            owner of the object. Raises a permission denied error if the user does not
            own the object.

        partial_update(request, *args, **kwargs):
            Handles partial updates to the object. Delegates the operation to the parent
            class's implementation.
    """

    permission_classes = [IsAuthenticated]
    queryset = Shortener.objects.all()
    serializer_class = ShortenerUpdateSerializer

    def get_object(self):
        obj = super().get_object()
        if obj.user != self.request.user:
            self.permission_denied(self.request)
        return obj

    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)


class ShortenerDelateView(generics.DestroyAPIView):
    """
    ShortenerDelateView is a view that handles the deletion of Shortener objects.
    It ensures that only authenticated users can delete objects and restricts access
    to objects owned by the requesting user.

    Attributes:
        permission_classes (list): Specifies the permissions required to access this view.
        queryset (QuerySet): Defines the set of Shortener objects available for deletion.

    Methods:
        get_object():
            Retrieves the object to be deleted. Ensures that the requesting user is the
            owner of the object. If the user does not own the object, access is denied.
    """

    permission_classes = [IsAuthenticated]
    queryset = Shortener.objects.all()

    def get_object(self):
        obj = super().get_object()
        if obj.user != self.request.user:
            self.permission_denied(self.request)
        return obj
