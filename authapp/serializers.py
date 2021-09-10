from .models import User
from rest_framework import serializers
from . models import *
from rest_framework.validators import UniqueValidator
from django.contrib.auth.hashers import make_password
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