from django.urls import path

from rest_framework_simplejwt.views import TokenRefreshView

from .views import *

app_name = 'auth'

urlpatterns = [
    path('login', LoginView.as_view(), name='login'),
    path('register', RegisterView.as_view(), name='register'),
    path('email-verify', VerifyEmail.as_view(), name='email-verify'),
    path('token/refresh', TokenRefreshView.as_view(), name='refresh-token'),
    path('request-reset-password', RequestResetPasswordView.as_view(), 
        name='password-reset-request'),
    path('password-reset/<uidb64>/<token>', ResetPasswordTokenCheckView.as_view(), 
        name='password-reset-confirm'),
    path('reset-password-complete', SetNewPasswordView.as_view(), 
        name='password-reset-complete'),
]

