from pydoc import resolve

from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from django.shortcuts import get_object_or_404

from users.models import BaseUser
from users.validators import number_validator, letter_validator, special_char_validator


class LoginView(APIView):
    class InputSerializer(serializers.Serializer):
        email = serializers.EmailField(max_length=255)
        password = serializers.CharField()

    class OutputSerializer(serializers.ModelSerializer):
        token = serializers.SerializerMethodField('get_token')

        class Meta:
            model = BaseUser
            fields = ('email', 'is_active', 'last_login', 'token')

        def get_token(self, user):
            token_class = RefreshToken
            refresh_token = token_class.for_user(user)
            access_token = refresh_token.access_token
            data = {
                'access': str(access_token),
                'refresh': str(refresh_token),
            }

            return data

    def post(self, request):
        serializer = self.InputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        user = get_object_or_404(BaseUser, email=validated_data['email'])
        request_raw_password = validated_data['password']

        if not user.check_password(request_raw_password):
            raise serializers.ValidationError('Incorrect password.')

        return Response(self.OutputSerializer(user, context={'request': request.data}).data)


class RegisterView(APIView):
    class InputSerializer(serializers.Serializer):
        email = serializers.EmailField(max_length=255)
        password = serializers.CharField(
            validators=[
                number_validator,
                letter_validator,
                special_char_validator,
            ]

        )
        confirm_password = serializers.CharField()

        def validate_email(self, email):
            if BaseUser.objects.filter(email__iexact=email).exists():
                raise serializers.ValidationError('this email is already taken')

            return email

        def validate(self, data):
            if not data.get("password") or not data.get("confirm_password"):
                raise serializers.ValidationError('password and confirm_password fields must not be empty')
            elif data.get("confirm_password") != data.get("password"):
                raise serializers.ValidationError('password and confirm_password fields must match')

            return data

    class OutputSerializer(serializers.ModelSerializer):
        class Meta:
            model = BaseUser
            fields = ('email', 'created_at', 'updated_at', 'is_active')

    def post(self, request):
        serializer = self.InputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        user = BaseUser.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
        )

        return Response(self.OutputSerializer(user, context={'request': request.data}).data)
