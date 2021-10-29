from . views import FacebookSocialAuthView, GoogleSocialAuthView, TwitterSocialAuthView
from django.urls import path
urlpatterns = [
    path('google/', GoogleSocialAuthView.as_view()),
    path('facebook/', FacebookSocialAuthView.as_view()),
    path('twitter/', TwitterSocialAuthView.as_view()),
]