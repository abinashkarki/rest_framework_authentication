from django.contrib.auth.models import User
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
    class Meta:
        model = User
        fields=('id', 'username', 'password')
        extra_kwargs = {
            'password':{'write_only': True},
        }

    def create(self, validated_data):
        user = User.objects.create_user(validated_data['username'],
        password = validated_data['password'],
        email = validated_data['email'])
        return user

    def validate_password(self, value: str) -> str:
        """
        Hash value passed by user.

        :param value: password of a user
        :return: a hashed version of the password
        """
        return make_password(value)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'