from datetime import timedelta

import redis
from django.conf import settings
from django.contrib.auth import authenticate
from django.utils import timezone
from rest_framework import status
from rest_framework.generics import UpdateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView as BaseTokenRefreshView

from utils import decode_token, send_activation_email

from .forms import PasswordResetForm
from .models import RefreshTokenBlackList, User
from .permissions import IsTokenBlacklisted
from .serializers import (
    EmailChangeSerializer,
    PasswordChangeSerializer,
    UserLoginSerializer,
    UserRegisterSerializer,
    UserUpdateSerializer,
)


class UserRegisterView(APIView):
    """
    API view for user registration.

    Handles POST requests to register a new user. Validates incoming data using
    UserRegisterSerializer, creates the user, sends an activation email, and returns
    JWT tokens (refresh and access) along with user data upon successful registration.

    Returns:
        - 201 CREATED: On successful registration, returns user data and JWT tokens.
        - 422 UNPROCESSABLE ENTITY: If validation fails, returns serializer errors.
    """

    def post(self, request) -> Response:
        srz_data = UserRegisterSerializer(data=request.data)
        if srz_data.is_valid():
            vd = srz_data.validated_data
            user = srz_data.create(validated_data=vd)
            send_activation_email(user=user, request=request, _type="confirm email")

            refresh = RefreshToken.for_user(user)
            token_data = {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }

            return Response(
                data={"user": srz_data.data, **token_data},
                status=status.HTTP_201_CREATED,
            )

        return Response(
            data=srz_data.errors, status=status.HTTP_422_UNPROCESSABLE_ENTITY
        )


class UserLoginView(APIView):
    """
    UserLoginView handles user authentication via POST requests.

    POST:
        Authenticates a user using provided username and password.
        If authentication is successful:
            - Updates the user's last_login timestamp.
            - Returns JWT refresh and access tokens.
        If authentication fails:
            - Returns an error message with HTTP 400 status.
        If input data is invalid:
            - Returns serializer validation errors with HTTP 400 status.

    Request data:
        - username: str
        - password: str

    Response:
        - On success: {"refresh": <refresh_token>, "access": <access_token>}
        - On failure: {"error": "Invalid username or password"} or serializer errors
    """

    def post(self, request) -> Response:
        srz_data = UserLoginSerializer(data=request.data)
        if srz_data.is_valid():
            vd = srz_data.validated_data

            user = authenticate(username=vd["username"], password=vd["password"])

            if user is not None:
                user.last_login = timezone.now()
                user.save(update_fields=["last_login"])
                refresh = RefreshToken.for_user(user)
                token_data = {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
                return Response(data=token_data, status=status.HTTP_200_OK)

            return Response(
                {"error": "Invalid username or password"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(data=srz_data.errors, status=status.HTTP_400_BAD_REQUEST)


class ConfirmEmailView(APIView):
    """
    APIView for confirming a user's email address via a token.

    This view handles GET requests with a token parameter, decodes the token to retrieve the user's email,
    and activates the user account if the token is valid and the user exists. If the token is invalid or expired,
    or if the user does not exist, appropriate error messages and templates are rendered.

    Methods:
        get(request, token):
            Decodes the token and activates the user if valid. Renders success or failure templates based on the outcome.

    Attributes:
        renderer_classes (list): Specifies the renderer to use for HTML templates.
    """

    renderer_classes = [TemplateHTMLRenderer]

    def get(self, request, token) -> Response:
        email = decode_token(token, salt=settings.ITD_EMAIL_CONFIRM_SALT)
        if email is None:
            return Response(
                {"message": "Invalid or expired token"},
                template_name="email_confirm_failed.html",
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(email=email)
            if not user.is_active:
                user.is_active = True
                user.save()
            return Response(
                template_name="email_confirm.html", status=status.HTTP_200_OK
            )

        except User.DoesNotExist:
            return Response(
                {"message": "User does not exist"},
                template_name="email_confirm_failed.html",
                status=status.HTTP_400_BAD_REQUEST,
            )


class UserUpdateView(UpdateAPIView):
    """
    API view for updating the authenticated user's information.

    This view allows an authenticated user to update their own profile data.
    It uses the `UserUpdateSerializer` to validate and save changes to the user model.
    Access is restricted to authenticated users whose tokens are not blacklisted.

    Methods:
        get_object(): Returns the current authenticated user instance.

    Permissions:
        - IsAuthenticated: Ensures the user is logged in.
        - IsTokenBlacklisted: Ensures the user's token is valid and not blacklisted.
    """

    queryset = User.objects.all()
    serializer_class = UserUpdateSerializer
    permission_classes = [IsAuthenticated, IsTokenBlacklisted]

    def get_object(self):
        return self.request.user


class UserLogoutView(APIView):
    """
    UserLogoutView handles user logout by blacklisting access and refresh tokens.

    POST:
        - Requires 'access' and 'refresh' tokens in the request data.
        - Blacklists the access token in Redis until its expiry.
        - Stores the refresh token in the database blacklist with its expiry.
        - Returns a success message upon successful logout.
        - Returns an error message if tokens are missing or invalid.

    Permissions:
        - Requires the user to be authenticated.
        - Requires the token to not be blacklisted.
    """

    permission_classes = [IsAuthenticated, IsTokenBlacklisted]

    def post(self, request) -> Response:
        access_token = request.data.get("access")
        refresh_token = request.data.get("refresh")

        if not access_token or not refresh_token:
            return Response(
                {"detail": "Access and refresh tokens are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        redis_instance = redis.Redis.from_url(settings.CACHES["default"]["LOCATION"])

        try:
            access_token_obj = AccessToken(access_token)
            access_expiry = access_token_obj["exp"]
            exp_time = int(
                (
                    timedelta(seconds=access_expiry - int(timezone.now().timestamp()))
                ).total_seconds()
            )

            if access_expiry:
                redis_instance.setex(access_token, exp_time, "blacklisted")

            refresh_token_obj = RefreshToken(refresh_token)
            refresh_expiry = refresh_token_obj["exp"]

            if refresh_expiry:
                RefreshTokenBlackList.objects.create(
                    user=request.user,
                    token=refresh_token,
                    expires_at=timezone.now()
                    + timedelta(
                        seconds=refresh_expiry - int(timezone.now().timestamp())
                    ),
                )

        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {"detail": "Successfully logged out."}, status=status.HTTP_200_OK
        )


class UserDeleteView(APIView):
    """
    API view for deleting the authenticated user's account.

    This view requires the user to be authenticated and the token to not be blacklisted.
    On a DELETE request, it deletes the current user and returns a success message.

    Methods:
        delete(request): Deletes the authenticated user and returns a confirmation response.

    Permissions:
        - IsAuthenticated: Ensures the user is logged in.
        - IsTokenBlacklisted: Ensures the token is valid and not blacklisted.
    """

    permission_classes = [IsAuthenticated, IsTokenBlacklisted]

    def delete(self, request) -> Response:
        user = request.user
        user.delete()
        return Response({"message": "Account deleted successfully."})


class TokenRefreshView(BaseTokenRefreshView):
    """
    View for handling JWT token refresh requests.

    This view extends the BaseTokenRefreshView to add custom logic for checking
    if the provided refresh token has been blacklisted. If the token is found in
    the RefreshTokenBlackList, an error response is returned indicating the token
    is invalid. Otherwise, the standard token refresh process is executed.

    Methods:
        post(request, *args, **kwargs) -> Response:
            Handles POST requests to refresh JWT tokens, with blacklist validation.
    """

    def post(self, request, *args, **kwargs) -> Response:
        refresh_token = request.data.get("refresh")
        if RefreshTokenBlackList.objects.filter(token=refresh_token).exists():
            return Response(
                {"detail": "Invalid Token"}, status=status.HTTP_400_BAD_REQUEST
            )

        return super().post(request, *args, **kwargs)


class EmailChangeView(APIView):
    """
    APIView for handling user email change requests.

    This view allows authenticated users to request an email address change.
    Upon receiving a valid request, it updates the user's `new_email` field and sends a confirmation email to the new address.

    Permissions:
        - IsAuthenticated: Ensures the user is logged in.
        - IsTokenBlacklisted: Ensures the user's token is not blacklisted.

    Methods:
        post(request):
            Accepts a POST request with the new email address.
            Validates the input using EmailChangeSerializer.
            If valid, updates the user's `new_email` field and sends a confirmation email.
            Returns a success message if the email was sent, or validation errors otherwise.
    """

    permission_classes = [IsAuthenticated, IsTokenBlacklisted]

    def post(self, request) -> Response:
        srz_data = EmailChangeSerializer(data=request.data)
        if srz_data.is_valid():
            user = request.user
            new_email = srz_data.validated_data["new_email"]

            user.new_email = new_email
            user.save()

            send_activation_email(
                user=user,
                request=request,
                new_email=new_email,
                _type="confirm change email",
            )
            return Response(
                {"message": "Confirmation email sent to new address."},
                status=status.HTTP_200_OK,
            )

        return Response(srz_data.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailChangeConfirmView(APIView):
    """
    APIView for confirming a user's email change request.

    This view handles GET requests with a token parameter, which is used to verify and confirm the user's new email address.
    If the token is valid and matches a user with a pending email change, the user's email is updated and a success template is rendered.
    If the token is invalid, expired, or the user is not found, an error template is rendered.

    Methods:
        get(request, token):
            - Decodes the token to retrieve the new email address.
            - Updates the user's email if the token and user are valid.
            - Renders appropriate success or failure templates based on the outcome.

    Args:
        request (Request): The HTTP request object.
        token (str): The token used to verify the email change.

    Returns:
        Response: Renders either the success or failure template with appropriate status code.
    """

    renderer_classes = [TemplateHTMLRenderer]

    def get(self, request, token) -> Response:
        email = decode_token(token, salt=settings.ITD_EMAIL_CHANGE_SALT)

        if not email:
            return Response(
                {"message": "Invalid or expired token"},
                template_name="email_change_failed.html",
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(new_email=email)
            user.email = email
            user.new_email = None
            user.save()
            return Response(
                template_name="email_change_success.html", status=status.HTTP_200_OK
            )

        except User.DoesNotExist:
            return Response(
                {"message": "User not found."},
                template_name="email_change_failed.html",
                status=status.HTTP_404_NOT_FOUND,
            )


class PasswordChangeView(APIView):
    """
    APIView for initiating a password change process.

    This view handles POST requests containing user email for password change.
    If the provided data is valid, it sends a password change activation email
    to the user. Otherwise, it returns validation errors.

    Methods:
        post(request):
            Accepts email in request data, validates it, sends password change link
            if valid, or returns errors if invalid.
    """

    def post(self, request):
        srz_data = PasswordChangeSerializer(data=request.data)
        if srz_data.is_valid():
            email = srz_data.validated_data["email"]
            user = User.objects.get(email=email)
            send_activation_email(user=user, request=request, _type="change password")
            return Response(
                {"message": "Password change link has been sent to your email."},
                status=200,
            )
        else:
            return Response(
                {"message": "Invalid input", "errors": srz_data.errors}, status=400
            )


class PasswordChangeConfirmView(APIView):
    """
    APIView for confirming and processing password change requests via a token.

    This view handles both GET and POST requests:
    - GET: Renders the password change form if the token is valid, otherwise shows an error page.
    - POST: Validates the submitted form and updates the user's password if the token is valid and the form is correct.
        On success, renders a success page; on failure, renders the form with errors or an error page if the token is invalid.

    Attributes:
            renderer_classes (list): Specifies the renderer for HTML templates.
            base_template_name (str): Template for the password change form.
            success_template_name (str): Template for successful password change.
            failed_template_name (str): Template for failed password change.

    Methods:
            get(request, token): Renders the password change form or error page based on token validity.
            post(request, token): Processes the password change form, updates the password, and renders appropriate templates.
    """

    renderer_classes = [TemplateHTMLRenderer]
    base_template_name = "password_change.html"
    success_template_name = "password_change_success.html"
    failed_template_name = "password_change_failed.html"

    def get(self, request, token):
        email = decode_token(token, salt=settings.ITD_RESET_PASSWORD_SALT)
        if email is None:
            return Response(
                {"message": "Invalid or expired token"},
                template_name=self.failed_template_name,
                status=status.HTTP_404_NOT_FOUND,
            )

        form = PasswordResetForm()
        return Response(
            {"token": token, "form": form},
            template_name=self.base_template_name,
            status=status.HTTP_200_OK,
        )

    def post(self, request, token):
        email = decode_token(token, salt=settings.ITD_RESET_PASSWORD_SALT)
        if email is None:
            return Response(
                {"message": "Invalid or expired token"},
                template_name=self.failed_template_name,
                status=status.HTTP_404_NOT_FOUND,
            )

        form = PasswordResetForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data.get("password")

            try:
                user = User.objects.get(email=email)
                user.set_password(password)
                user.save()
                return Response(
                    {"message": "your password has been successfully changed"},
                    template_name=self.success_template_name,
                    status=status.HTTP_200_OK,
                )

            except User.DoesNotExist:
                return Response(
                    {"message": "Invalid or expired token"},
                    template_name=self.failed_template_name,
                    status=status.HTTP_404_NOT_FOUND,
                )

        else:
            return Response(
                {"token": token, "form": form},
                template_name=self.base_template_name,
                status=status.HTTP_400_BAD_REQUEST,
            )
