from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("register/", views.UserRegisterView.as_view(), name="register"),
    path("login/", views.UserLoginView.as_view(), name="login"),
    path("update/", views.UserUpdateView.as_view(), name="update"),
    path("logout/", views.UserLogoutView.as_view(), name="logout"),
    path("delete/", views.UserDeleteView.as_view(), name="delete"),
    path(
        "confirm/<str:token>/", views.ConfirmEmailView.as_view(), name="confirm_email"
    ),
    path("change-email/", views.EmailChangeView.as_view(), name="change_email"),
    path(
        "confirm-change-email/<str:token>/",
        views.EmailChangeConfirmView.as_view(),
        name="confirm_change_email",
    ),
    path(
        "change-password/", views.PasswordChangeView.as_view(), name="change_password"
    ),
    path(
        "confirm-change-password/<str:token>/",
        views.PasswordChangeConfirmView.as_view(),
        name="confirm_change_password",
    ),
    path("token/refresh/", views.TokenRefreshView.as_view(), name="token_refresh"),
]
