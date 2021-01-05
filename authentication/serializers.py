from django.contrib import auth
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from .models import User
from .utils import Util


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(max_length=16, min_length=4)

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'password2']

    def validate(self, attrs):
        username = attrs.get('username', '')
        if not username.isalnum():
            raise serializers.ValidationError('The username should only contain alphanumeric characters')
        return attrs

    def save(self):
        user = User(
            email=self.validated_data['email'],
            username=self.validated_data['username'],
        )
        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        if password != password2:
            raise serializers.ValidationError({'password': 'Passwords must match.'})

        user.set_password(password)
        user.save()
        return user

    # def create(self, validate_data):
    #     return User.objects.create_user(**validate_data)


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=7)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(max_length=16, min_length=4, read_only=True)
    tokens = serializers.CharField(max_length=68, min_length=6, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentions.')
        if not user.is_verified:
            raise AuthenticationFailed('Account is not verified.')
        if not user.is_active:
            raise AuthenticationFailed('Account is not active.')

        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens,
        }

        return super().validate(attrs)


class RequestResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, min_length=7)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    token = serializers.CharField(max_length=555, min_length=1, write_only=True)
    uidb64 = serializers.CharField(max_length=68, min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid.', 401)

            user.set_password(password)
            user.save()

            return user

        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid.', 401)

        return super().validate(attrs)
