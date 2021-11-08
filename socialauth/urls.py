from . views import FacebookSocialAuthView, GoogleSocialAuthView, TwitterSocialAuthView
from django.urls import path

from socialauth import views
urlpatterns = [
    path('google/', GoogleSocialAuthView.as_view()),
    path('facebook/', FacebookSocialAuthView.as_view()),
    path('twitter/', TwitterSocialAuthView.as_view()),
]