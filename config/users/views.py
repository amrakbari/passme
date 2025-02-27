import datetime
from enum import verify
from pydoc import resolve
from typing import NoReturn

from cryptography.fernet import Fernet
from django.http import HttpResponse
from rest_framework import serializers, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail, BadHeaderError

from common.mixins import ApiAuthMixin
from common.permissions import IsActive
from config.settings import SECRET_KEY, APPLICATION_HOST, EMAIL_HOST_USER, APPLICATION_PORT
from users.models import BaseUser
from users.validators import number_validator, letter_validator, special_char_validator


class VerifyAPIView(APIView):
    def get(self, request: Request, hashed_user_id: str) -> HttpResponse:
        cipher = Fernet(SECRET_KEY)
        # decrypt the hashed user_id
        user_id = cipher.decrypt(hashed_user_id.encode()).decode()

        # activate user
        BaseUser.objects.filter(id=user_id).update(is_active=True)

        return HttpResponse('user verified successfully',status=status.HTTP_200_OK)




class LoginView(APIView):
    authentication_classes = []
    permission_classes = (IsActive,)
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
        self.check_object_permissions(request, user)

        request_raw_password = validated_data['password']

        if not user.check_password(request_raw_password):
            raise serializers.ValidationError('Incorrect password.')
        user.last_login = datetime.datetime.now()
        user.save()
        return Response(self.OutputSerializer(user, context={'request': request.data}).data)

class SendVerificationEmailView(APIView):
    class InputSerializer(serializers.Serializer):
        email = serializers.EmailField(max_length=255)
        password = serializers.CharField(max_length=255)

    def post(self, request):
        serializer = self.InputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        user = get_object_or_404(BaseUser, email=validated_data['email'])
        if not user.check_password(validated_data['password']):
            raise serializers.ValidationError('Incorrect password.')

        cipher = Fernet(SECRET_KEY)
        hashed_user_id = cipher.encrypt(str(user.id).encode()).decode('utf-8')
        subject = 'email verification - passme'
        verify_url = f'http://{APPLICATION_HOST}:{APPLICATION_PORT}/users/verify/{hashed_user_id}'
        message = f'please click the link to verify your email address: {verify_url}'
        from_email = EMAIL_HOST_USER
        recipient_list = [user.email]
        try:
            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
        except Exception as e:
            HttpResponse('email not sent successfully | error:', e, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return HttpResponse('email sent successfully')



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

    def send_verification_mail(self, hashed_user_id: str, user_email: str):
        subject = 'email verification - passme'
        verify_url = f'http://{APPLICATION_HOST}/users/verify/{hashed_user_id}'
        message = f'please click the link to verify your email address: {verify_url}'
        from_email = EMAIL_HOST_USER
        recipient_list = [user_email]
        try:
            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
        except Exception as e:
            raise e

    def post(self, request):
        serializer = self.InputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        user = BaseUser.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
        )

        cipher = Fernet(SECRET_KEY)
        hashed_user_id = cipher.encrypt(str(user.id).encode()).decode('utf-8')
        email_result = self.send_verification_mail(hashed_user_id, str(user.email))


        return Response(self.OutputSerializer(user, context={'request': request.data}).data)
