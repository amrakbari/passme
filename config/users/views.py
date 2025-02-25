from pydoc import resolve

from rest_framework import serializers
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from users.models import BaseUser
from users.validators import number_validator, letter_validator, special_char_validator


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
        token = serializers.SerializerMethodField('get_token')
        class Meta:
            model = BaseUser
            fields = ('email', 'created_at', 'updated_at', 'token')

        def get_token(self, user):
            token_class = RefreshToken
            refresh = token_class.for_user(user)
            access = refresh.access_token
            data = {
                'refresh': str(refresh),
                'access': str(access),
            }
            return data

    def post(self, request):
        ...