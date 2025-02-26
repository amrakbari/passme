from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

from common.permissions import IsActive


class ApiAuthMixin:
    authentication_classes = [
        JWTAuthentication,
    ]
    permission_classes = (
        IsAuthenticated,
        IsActive,
    )

