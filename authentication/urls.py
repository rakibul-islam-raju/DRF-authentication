from django.urls import path

from .views import *

app_name = 'auth'

urlpatterns = [
    path('register', RegisterView.as_view(), name='register'),
    path('email-verify/', VerifyEmail.as_view(), name='email-verify'),
]

