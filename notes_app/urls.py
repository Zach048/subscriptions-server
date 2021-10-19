from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from notes_app import views
from rest_framework_simplejwt import views as jwt_views

urlpatterns = [
    path('token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    # path("login/", views.login_view, name="login-view"),
    # path("logout/", views.logout_view, name="logout-view"),
    path("users/profile/", views.Profile.as_view(), name="user-profile",),
    # path("auth/", views.exchange_token, name="auth",),
    path("auth/oidc/callback", views.auth_complete, name="auth_callback",),
    path('subscriptions/', views.SubscriptionList.as_view()),
    path('subscriptions/<int:pk>/', views.SubscriptionDetail.as_view()),
]