# from os import settings
from .utils import Util
from django.http import response
from authapp.serializers import RegisterSerialzer
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import User
from rest_framework.authtoken.models import Token
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from rest_framework import status
import jwt
from django.conf import settings
from django.core import exceptions
# Create your views here.
class RegisterUser(APIView):
    serialzer_class = RegisterSerialzer
    def post(self, request):
        user = request.data
        serializer = self.serialzer_class(data = user)
        serializer.is_valid(raise_exception = True)     
        serializer.save()
        user_data = serializer.data
        # user = User.objects.get(username=serializer.data['username'])
        # print(user.id)
        # token = Token.objects.create(user=user)
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


class VerifyEmail(APIView):
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            user.is_verified = True
            # if not user.is_verified:
            user.save()
            return Response({'email':'successfuly activated'}, status=status.HTTP_200_OK)
        # except jwt.ExpiredSignatureError as identifier:
        except jwt.ExpiredSignatureError:
            return Response({'error':'Activation Expired expired'}, status=status.HTTP_400_BAD_REQUEST)
        # except jwt.exceptions.DecodeError as identifier:
        except jwt.exceptions.DecodeError:
            return Response({'error':'invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        # except jwt.ExpiredSignatureError:
        #     msg = 'Signature has expired.'
            # raise exceptions.AuthenticationFailed(msg)
        # except jwt.DecodeError:
        #     msg = 'Error decoding signature.'
        #     # raise exceptions.AuthenticationFailed(msg)
        # except jwt.InvalidTokenError:
        #     raise exceptions.AuthenticationFailed()





 


# # @csrf_exempt
# class LoginView(APIView):
#     def post(self, request):
#         username = request.data['username']
#         password = request.data['password']
#         user = User.objects.get(username=username)
#         token = Token.objects.create(user = user)
#         return Response({'message': 'loggedin','status':200, 'token':token})


class Mesg(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        content={
            'message':'you are logged in'
        }
        return Response(content)
