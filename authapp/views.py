# from os import settings
from os import stat
from django.contrib.auth import logout
from django.contrib.auth import tokens
from django.db.models.fields import DateField

from authapp import serializers
from .utils import Util
from django.http import response
from authapp.serializers import LoginSerializer, RegisterSerialzer, UserSerializer,LogoutSerializer,EmailVerificationSerializer,ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer, ChangePasswordSerializer, ChangePasswordSerializer2, TotalUserSerializer,RegisteredUserFilterSerializer
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
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
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
        try:
            user = User.objects.get(email=email)
            if user.is_verified:
                return Response({'msg':'User is already verified'})
            token = RefreshToken.for_user(user).access_token
            current_site= get_current_site(self.request).domain
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
    serializer_class = EmailVerificationSerializer
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(id=payload['user_id'])
            if user.is_verified:
                return Response({'msg':'User already verified!'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                user.is_verified = True
                user.is_active = True
                user.save()
                return Response({'email':'successfuly activated','status':'status.HTTP_200_OK'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({'error':'Activation Expired','status':'status.HTTP_400_BAD_REQUEST'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response({'error':'invalid token','status':'status.HTTP_400_BAD_REQUEST'}, status=status.HTTP_400_BAD_REQUEST)


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
            user = request.user
            user.active = False
            user.save()
            return Response({'msg':'User Successfully logged out','status':'status.HTTP_204_NO_CONTENT'})
        except TokenError:
            return Response({'msg':'token is already blacklisted or is not valid','status':'status.HTTP_400_BAD_REQUEST'})


def all1(request):
    return render (request, "welcome.html")


def googlepage(request):
    return render(request, 'login with google.html')


def facebookpage(request):
    return render(request, 'login with facebook.html')


def twitterpage(request):
    return render(request, 'login with twitter.html')


class RequestPasswordResetEmail(APIView):
    serializer_class = ResetPasswordEmailRequestSerializer
    
    def post(self, request):
        serialzer = self.serializer_class(data=request.data)

        email = request.data.get('email','')
        
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            print(user.username)
            uidb64=urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site= get_current_site(request=request).domain
            relativeLink = reverse('password-reset-confirm', kwargs={'uidb64':uidb64, 'token':token})
            absurl = 'http://'+current_site+relativeLink
            email_body = 'Hello, \n use this link to reset your password \n' + absurl
            data = {'email_body':email_body,'to_email':user.email,
                    'email_subject':'Password reset request'}
            Util.send_email(data)
            print("sent email")
        return Response({'Success':'We have sent you a link to reset your password'},status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(APIView):
    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error':"Token is not valid, please request a new one"}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({'success':True, 'message':'Credentials Valid', 'uidb64':uidb64, 'token':token}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError:
                return Response({'error':"Token is not valid, please request a new one"}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIVIew(APIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"success":True, "message":"Password Reset Success"}, status=status.HTTP_200_OK)


class ChangePassword(APIView):
    serializer_class=ChangePasswordSerializer
    serializer_class2=ChangePasswordSerializer2
    model = User
    permission_classes = [IsAuthenticated]

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def put(self,request, *args, **kwargs):
        self.object = self.get_object()
    
        if self.object.auth_provider != "email": 
            serializer = self.serializer_class2(data=request.data)
            print(serializer.initial_data)
            if serializer.is_valid():
                self.object.set_password(serializer.data.get("new_password"))
                self.object.auth_provider = "email"
                print("self.object.auth_provider"+self.object.auth_provider)
                self.object.save()
                response={
                        'status':'success',
                        'code':status.HTTP_200_OK,
                        'message':"Password changed Successfully",
                    }        
                return Response(response)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)                  
        else:
            #check old password
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                if not self.object.check_password(serializer.data.get("old_password")):
                    return Response({'error':["Wrong_password"]}, status=status.HTTP_400_BAD_REQUEST)
                self.object.set_password(serializer.data.get("new_password"))
                self.object.save()
                response={
                    'status':'success',
                    'code':status.HTTP_200_OK,
                    'message':"Password changed Successfully",
                }        
                return Response(response)                
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TotalUser(APIView):
    serializer = TotalUserSerializer
    def get(self, *args, **kwargs):
        all_user=User.objects.all()
        last_user = len(all_user)
        return Response(
            {'totalUser':last_user}
        )

        
class TotalActiveUser(APIView):
    serializer = TotalUserSerializer
    def get(self, *args, **kwargs):
        active_user = User.objects.filter(active=True)
        users = []
        for i in active_user:
            users.append(i.username)
        totalActiveUser=len(active_user)
        return Response({"total active user":totalActiveUser, 'users': users})


import datetime
class RegisteredUserFilter(APIView):
    serializer = RegisteredUserFilterSerializer

    def get(self, from_date, to_date):
        userondate = User.objects.filter(created_at__range=[from_date, to_date])
       
        return Response({"User": userondate})

#  userondate = User.objects.filter(created_at__gte=datetime.date(fromDate),      
                                #  created_at__lte=datetime.date(toDate))[0]

        # user = User.objects.filter(username="karkiabinash")[0]
        # print(user.created_at)

    # def get(self, *args, **kwargs):
    #     userondate = User.objects.filter(created_at__range=['2011-10-11', '2022-12-31']).__dict__
    #     print(userondate)
    #     users = []
    #     for i in userondate:
    #         users.append(i)      
    #     return Response({"User": users})
