from django.urls import path

from . import views

app_name = "shortener"

urlpatterns = [
    path("create/", views.ShortenerView.as_view(), name="create_url"),
    path("list/", views.ShortenerListView.as_view(), name="list_urls"),
    path("detail/<int:pk>", views.ShortenerDetailView.as_view(), name="detail_url"),
    path("update/<int:pk>/", views.ShortenerUpdateView.as_view(), name="update_url"),
    path("delete/<int:pk>/", views.ShortenerDelateView.as_view(), name="delete_url"),
    path(
        "<str:short_code>/", views.RedirectShortURLView.as_view(), name="redirect_url"
    ),
]
