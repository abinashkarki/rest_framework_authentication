from django.http import response
from authapp.serializers import RegisterSerialzer
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticated
# Create your views here.
class RegisterUser(APIView):
    def post(self, request):
        serializer = RegisterSerialzer(data = request.data)

        serializer.is_valid(raise_exception = True)     
        serializer.save()
        # user = User.objects.get(username=serializer.data['username'])
        # print(user.id)
        # token = Token.objects.create(user=user)

        return Response(serializer.data)

# from django.contrib.auth import authenticate
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
