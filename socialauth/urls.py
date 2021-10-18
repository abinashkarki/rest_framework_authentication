from . views import GoogleSocialAuthView
from django.urls import path
urlpatterns = [
    path('google/', GoogleSocialAuthView.as_view()),
]