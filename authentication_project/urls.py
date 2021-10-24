"""authentication_project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from os import name
from django.contrib.auth import logout
from authapp.views import ChangePassword, LoginAPIView, LogoutAPIView, RegisterUser, Mesg, ResendVerifyEmail, SetNewPasswordAPIVIew, UserDetailView, VerifyEmail,PasswordTokenCheckAPI,RequestPasswordResetEmail, googlepage
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from authapp import views
from django.conf.urls.static import static
from django.conf import settings
from django.views.static import serve

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api-auth/', include('rest_framework.urls')),
    path('register/', RegisterUser.as_view()),
    path('ResendRegisterLink/', ResendVerifyEmail.as_view()),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('UserDetail/', UserDetailView.as_view(), name='my-detail'),
    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), 
    path('log/', Mesg.as_view()),
    path('email-verify/', VerifyEmail.as_view(), name = 'email-verify'),
    path('request-reset-email/', RequestPasswordResetEmail.as_view(), name='request-reset-email'),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete/', SetNewPasswordAPIVIew.as_view(), name='password-reset-complete'),
    path('change-password/', ChangePassword.as_view(), name='change-password'),
    path("all/", views.all1,name="all"),
    path("socialLogin/", views.googlepage),
    path("", include('social_django.urls', namespace='social')),
    # path("socialLogout", views.logout, name="social-logout")
    path('social_auth/', include('socialauth.urls')),
]
