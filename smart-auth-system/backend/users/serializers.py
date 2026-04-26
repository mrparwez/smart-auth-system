from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth import authenticate

class RegisterSerializer(serializers.ModelSerializer):
    password=serializers.CharField(write_only=True)

    class Meta:
        model=CustomUser
        fields=['email','username','password']

    def create(self,validate_date):
        user=CustomUser.objects.create_user(
            email=self.validated_data['email'],
            username=self.validated_data['username'],
            password=self.validated_data['password']
        )
        return user
    

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(
            username=data['email'],
            password=data['password']
        )

        if not user:
            raise serializers.ValidationError("Invalid Credentials")

        data['user'] = user
        return data