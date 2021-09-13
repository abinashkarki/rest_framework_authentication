from .models import User
from rest_framework import serializers
from . models import *
from rest_framework.validators import UniqueValidator
from django.contrib.auth.hashers import make_password
from rest_framework.exceptions import AuthenticationFailed
from django.contrib import auth
from rest_framework.response import Response
from rest_framework import status
#this does not hash the password
# class RegisterSerializer(serializers.ModelSerializer):
#     email = serializers.EmailField(
#             required=True,)
#     class Meta: 
#         model = User
#         fields = ['id', 'username', 'email', 'password']

class RegisterSerialzer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True,
        validators = [UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(max_length=68, min_length = 6, write_only = True)
    class Meta:
        model = User
        fields=['id', 'email','username', 'password']



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


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(max_length=68, min_length=6, write_only = True)
    username = serializers.CharField(
        read_only=True
    )
    tokens = serializers.CharField(max_length=68, min_length=6, read_only=True)
 
    class Meta:
        model=User
        fields = ['email', 'username', 'password', 'tokens']


    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email, password=password)
        if user is None:
            return Response({'msg':'No such user'}, status=status.HTTP_401_UNAUTHORIZED)
            # raise AuthenticationFailed({'status':False,'message': ' username is worng'}, status=status.HTTP_401_UNAUTHORIZED)
        if not user.is_active:
            raise AuthenticationFailed({'msg':'Account is disabled'})
        if not user.is_verified:
            raise AuthenticationFailed({'msg': 'Email is not verified'})
        if not user:
            return Response({'msg':'Invalid credentials, try again'}, status=status.HTTP_401_Unauthorized)

        return{
            'email':user.email,
            'username':user.username,
            'tokens':user.tokens()
        }
        return super.validate(attrs)