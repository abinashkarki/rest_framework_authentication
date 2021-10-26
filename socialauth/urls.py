from . views import FacebookSocialAuthView, GoogleSocialAuthView
from django.urls import path
urlpatterns = [
    path('google/', GoogleSocialAuthView.as_view()),
    path('facebook/', FacebookSocialAuthView.as_view()),
]