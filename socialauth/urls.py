from . views import FacebookSocialAuthView, GoogleSocialAuthView, LinkedinSocialAuthView, TwitterSocialAuthView
from django.urls import path

from socialauth import views
urlpatterns = [
    path('google/', GoogleSocialAuthView.as_view()),
    path('facebook/', FacebookSocialAuthView.as_view()),
    path('twitter/', TwitterSocialAuthView.as_view()),
    path('linkedin/', LinkedinSocialAuthView.as_view()),
]