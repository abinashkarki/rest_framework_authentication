from django.urls import path, include
from django.urls.resolvers import URLPattern

from appcreator.views import RegisterApp

urlpatterns = [
    path('app-create/', RegisterApp.as_view(), name='create-app')
]