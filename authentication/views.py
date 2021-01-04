from django.shortcuts import get_object_or_404, reverse
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings

from rest_framework import generics, status, views
from rest_framework.response import Response

from rest_framework_simplejwt.tokens import RefreshToken

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .utils import Util
from .serializers import *
from .models import *

import jwt


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        # user = request.data
        serializer = RegisterSerializer(data=request.data or None)
        serializer.is_valid(raise_exception=True)
        serializer.save()
    
        # Generate token for new user
        user = get_object_or_404(User, email=serializer.data['email'])
        token = RefreshToken.for_user(user).access_token
    
        # send email
        current_site = get_current_site(request).domain
        relative_link = reverse('auth:email-verify')
        absolute_url = 'http://' + current_site + relative_link + '?token=' + str(token)
        mail_body = 'Hi ' + user.username + \
                    ' Use the link below to verify your email \n' + absolute_url
        data = {
            'subject': 'Email Verification',
            'body': mail_body,
            'email_to': user.email
        }
        Util.send_email(data)
    
        return Response({
            'data': serializer.data
        }, status=status.HTTP_201_CREATED)

    # def post(self, request):
    #     user = request.data
    #     serializer = self.serializer_class(data=user)
    #     serializer.is_valid(raise_exception=True)
    #     serializer.save()
    #     user_data = serializer.data
    #     user = User.objects.get(email=user_data['email'])
    #     token = RefreshToken.for_user(user).access_token
    #     current_site = get_current_site(request).domain
    #     relativeLink = reverse('auth:email-verify')
    #     absurl = 'http://' + current_site + relativeLink + "?token=" + str(token)
    #     email_body = 'Hi ' + user.username + \
    #                  ' Use the link below to verify your email \n' + absurl
    #     data = {'email_body': email_body, 'to_email': user.email,
    #             'email_subject': 'Verify your email'}

    #     Util.send_mail(data)
    #     return Response(user_data, status=status.HTTP_201_CREATED)


class VerifyEmail(views.APIView):
    serializer_class = EmailVerifySerializer

    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        print(token)
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if user.is_verified:
                return Response({
                    'msg': 'User already verified.'
                    }, status=status.HTTP_200_OK)
            else:
                user.is_verified = True
                user.save()
                return Response({
                    'email': 'Successfully activated'
                    }, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError as identifier:
            return Response({
                'error': 'Activation Expired'
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except jwt.exceptions.DecodeError as identifier:
            return Response({
                'error': 'Invalid token'
                }, status=status.HTTP_400_BAD_REQUEST)
