# from os import settings
from django.contrib.auth import logout
from .utils import Util
from django.http import response
from authapp.serializers import LoginSerializer, RegisterSerialzer, UserSerializer,LogoutSerializer
from django.shortcuts import redirect, render
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import User
from rest_framework.authtoken.models import Token
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from rest_framework import status
import jwt
from django.conf import settings
from django.core import exceptions
from rest_framework import permissions
# Create your views here.
class RegisterUser(APIView):
    serialzer_class = RegisterSerialzer
    def post(self, request):
        user = request.data
        serializer = self.serialzer_class(data = user)
        serializer.is_valid(raise_exception = True)     
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email = user_data['email'])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')
        absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
        email_body = 'Hi '+ user.username + 'user the link below to verify your email \n' + absurl
        data = {'email_body':email_body,'to_email':user.email,
                'email_subject':'Verify your email'}
        Util.send_email(data)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ResendVerifyEmail(APIView):
    serializer_class = RegisterSerialzer
    def post(self, request):
        data = request.data
        # email = data.get('email')
        email = data['email']
        print(email)
        try:
            user = User.objects.get(email=email)
            # print('hello')
            if user.is_verified:
                return Response({'msg':'User is already verified'})
            print (user.username)
            token = RefreshToken.for_user(user).access_token
            current_site= get_current_site(request).domain
            relativeLink = reverse('email-verify')
            
            absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
            email_body = 'Hi '+ user.username + ' this is the resent link to verify your email \n' + absurl

            data = {'email_body':email_body,'to_email':user.email,
                    'email_subject':'Verify your email'}
            Util.send_email(data)
            return Response({'msg':'The verification email has been sent'}, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response({'msg':'No such user, register first'})


class VerifyEmail(APIView):
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.filter(id=payload['user_id']).first()
            if user.is_verified:
                return Response({'msg':'User already verified!'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                user.is_verified = True
                # user.is_authenticated = True
                user.is_active = True
                # if not user.is_verified:
                user.save()
                return Response({'email':'successfuly activated'}, status=status.HTTP_200_OK)
        # except jwt.ExpiredSignatureError as identifier:
        except jwt.ExpiredSignatureError:
            return Response({'error':'Activation Expired expired'}, status=status.HTTP_400_BAD_REQUEST)
        # except jwt.exceptions.DecodeError as identifier:
        except jwt.exceptions.DecodeError:
            return Response({'error':'invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    serializer_class = LoginSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception = True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user
        return Response({
            'id':user.id,
            'username':user.username,
            'email':user.email
        })


class Mesg(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        content={
            'message':'you are logged in'
        }
        return Response(content)


class LogoutAPIView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception = True)
        try:
            serializer.save()
            return Response({'msg':'User Successfully logged out'})
        except TokenError:
            return Response({'msg':'token is already blacklisted or is not valid'})
