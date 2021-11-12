from appcreator.models import application
from rest_framework import serializers

class RegisterAppSerializer(serializers.ModelSerializer):
    class Meta:
        model = application
        fields = '__all__'

    # def create(self, validated_data):
    #     return Application.objects.create(**validated_data)
