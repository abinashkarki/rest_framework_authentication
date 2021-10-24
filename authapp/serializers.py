from django.contrib.auth import tokens
from django.db.models import fields
from django.http import request
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.hashers import make_password
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib import auth
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from .models import User
from .utils import Util
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
        

class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


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

        filtered_user_by_email = User.objects.filter(email=email)

        user = auth.authenticate(email=email, password=password)

        if filtered_user_by_email[0].auth_provider != 'email':
            raise AuthenticationFailed(
                detail="Please continue your login using "+filtered_user_by_email[0].auth_provider
            )
        print (user)
        if not user:
            raise AuthenticationFailed({'msg': 'No such user','status':'status.HTTP_401_UNAUTHORIZED'}, code=status.HTTP_401_UNAUTHORIZED)
        if user is None:
            raise AuthenticationFailed({'message': ' Your Email or Password is wrong', 'status':'status.HTTP_401_UNAUTHORIZED'}, code=status.HTTP_401_UNAUTHORIZED)
            # raise AuthenticationFailed({'message': ' username is wrong'})
        if not user.is_active:
            raise AuthenticationFailed({'msg':'Account is disabled', 'status':'status.HTTP_403_FORBIDDEN'},code=status.HTTP_403_FORBIDDEN)
        if not user.is_verified:
            raise AuthenticationFailed({'msg': 'Email is not verified', 'status':'status.HTTP_401_UNAUTHORIZED'}, code=status.HTTP_401_UNAUTHORIZED)

        return{
            'email':user.email,
            'username':user.username,
            'tokens':user.tokens()
        }
        return super.validate(attrs)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs
    def save(self, **kwargs):
        RefreshToken(self.token).blacklist()

  
class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)
    class Meta:
        fields=["email"]

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(min_length=1, write_only = True)
    uidb64 = serializers.CharField(min_length=1, write_only = True)

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
                raise AuthenticationFailed("The reset link is invalid", 401)
            user.set_password(password)
            user.save()

        except Exception as e:
            raise AuthenticationFailed("The reset link is invalid", 401)
        return super().validate(attrs)

class ChangePasswordSerializer(serializers.Serializer):
    model = User
    old_password=serializers.CharField(min_length=6)
    new_password = serializers.CharField(min_length=6)

    