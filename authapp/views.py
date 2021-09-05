from authapp.serializers import UserSerializer
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
# Create your views here.
class RegisterUser(APIView):
    def post(self, request):
        serializer = UserSerializer(data = request.data)

        if not serializer.is_valid():
            return Response({'message':'Credentials were not valid', 'status':403})      
        serializer.save()
        user = User.objects.get(username=serializer.data['username'])
        token = Token.objects.create(user=user)

        return Response({'token': str(token), 'status': 200})