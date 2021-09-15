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
from rest_framework_simplejwt.tokens import RefreshToken
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

class ResendVerifyEmail(APIView):
    serializer_class = RegisterSerialzer
    def post(self, request):
        data = request.data
        # email = data.get('email')
        email = data['email']
        print(email)
        try:
            user = User.objects.get(email=email)
       
            print('hello')
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

class LoginAPIView(APIView):
    serializer_class = LoginSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception = True)
        return Response(serializer.data, status=status.HTTP_200_OK)
        # return render(request, 'Welcome.html', {'data':serializer.data})

class UserDetailView(APIView):
    
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user
        return Response({
            'id':user.id,
            'username':user.username,
            'email':user.email
        })

        # content = {
        #     # 'id':User.id,
        #     'username':user.username,
        #     'email':user.email
        # }
        # return Response(content)

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
        serializer.save()

        return Response(status = status.HTTP_204_NO_CONTENT)

# class LogoutAPIView(APIView):
#     permission_classes = (IsAuthenticated,)

#     def post(self, request):
#         try:
#             refresh_token = request.data["refresh_token"]
#             token = RefreshToken(refresh_token)
#             token.blacklist()

#             return Response(status=status.HTTP_205_RESET_CONTENT)
#         except Exception as e:
#             return Response(status=status.HTTP_400_BAD_REQUEST)


# class LogoutAPIView(APIView):
#     serializer_class = LogoutSerializer
#     permission_classes = (permissions.IsAuthenticated, )

#     def post(self, request, *args):
#         sz = self.serializer_class(data=request.data)
#         sz.is_valid(raise_exception=True)
#         sz.save()
#         return Response(status=status.HTTP_204_NO_CONTENT)
