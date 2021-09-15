from django.db.models import fields
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.hashers import make_password
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib import auth
from rest_framework.response import Response
from rest_framework import status

from .models import User
from .models import *

class RegisterSerialzer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True,
        validators = [UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(max_length=68, min_length = 6, write_only = True)

    class Meta:
        model = User
        fields=['id','username','email','password']

    def create(self, validated_data):
        user = User.objects.create(
        email=validated_data['email'],
        username=validated_data['username'],
        password = make_password(validated_data['password']))
        user.save()
        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

class ResendVerificationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    # password = serializers.CharField(max_length=68, min_length=6, write_only = True)
    # username = serializers.CharField(
    #     read_only=True
    # )
    class Meta:
        # model = User
        fields = ['email']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.CharField()
    password = serializers.CharField(max_length=68, min_length=6, write_only = True)
    username = serializers.CharField(
        read_only=True
    )
    tokens = serializers.CharField(max_length=68, min_length=6, read_only=True)
 
    class Meta:
        model=User
        fields = ['email', 'username', 'password', 'tokens']


    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        user = auth.authenticate(email=email, password=password)
        print (user)
        if not user:
            raise AuthenticationFailed({'msg': 'No such user'}, code=status.HTTP_401_UNAUTHORIZED)
        if user is None:
            raise AuthenticationFailed({'message': ' Your Email or Password is wrong'}, code=status.HTTP_401_UNAUTHORIZED)
            # raise AuthenticationFailed({'message': ' username is wrong'})
        if not user.is_active:
            raise AuthenticationFailed({'msg':'Account is disabled'},code=status.HTTP_403_FORBIDDEN)
        if not user.is_verified:
            raise AuthenticationFailed({'msg': 'Email is not verified'}, code=status.HTTP_401_UNAUTHORIZED)
        
            return Response({'msg':'Invalid credentials, try again'}, status=status.HTTP_401_Unauthorized)

        return{
            'email':user.email,
            'username':user.username,
            'tokens':user.tokens()
        }
        return super.validate(attrs)

# class LogoutSerializer(serializers.Serializer):
#     refresh = serializers.CharField()
#     default_error_messages=(
#         {'bad_token': ('token is expired or invalid')}
#     )

#     def valdiate(self, attrs):
#         self.token = attrs['refresh']
#         return attrs

#     def save(self, **kwargs):
#         try:
#             RefreshToken(self.token).blacklist()
#             print('done')
#         except TokenError:
#             print('not done')
#             self.fail('bad_token')
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
            print('done')
            return Response({'msg':'token has been blacklisted'})
       

        except TokenError:
            print('not done')
            return Response({'msg':'token is expired or blacklisted'})



