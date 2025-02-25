from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import BaseUserManager  as BUM
from django.contrib.auth.models import PermissionsMixin
from django.db import models

from common.models import BaseModel


class BaseUserManager(BUM):
    def create_user(self, email, is_active=True, is_admin=False, password=None):
        if not email:
            raise ValueError('user must have an email address')

        user = self.model(email=self.normalize_email(email), is_active=is_active, is_admin=is_admin)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.full_clean()
        user.save()

        return user

class BaseUser(BaseModel, AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    USERNAME_FIELD = 'email'

    def __str__(self):
        return self.email

    def is_staff(self):
        return self.is_admin