"""p2 API Schemas (Django Ninja)"""
from typing import Optional
from ninja import ModelSchema, Schema
from django.contrib.auth.models import User
from p2.api.models import APIKey
from p2.core.auth_policy import PasswordChangeRequired

class UserSchema(ModelSchema):
    groups: list[str] = []
    password_change_required: bool = False

    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'email',
            'is_active',
            'is_staff',
            'is_superuser',
            'date_joined',
            'last_login',
        ]

    @staticmethod
    def resolve_groups(obj):
        return [g.name for g in obj.groups.all()]

    @staticmethod
    def resolve_password_change_required(obj):
        return PasswordChangeRequired.objects.filter(user=obj).exists()


class UserCreateSchema(Schema):
    username: str
    password: str
    email: str = ""
    is_active: bool = True
    is_superuser: bool = False
    groups: list[str] = []


class UserUpdateSchema(Schema):
    email: Optional[str] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None
    password: Optional[str] = None
    require_password_change: Optional[bool] = None
    groups: Optional[list[str]] = None

class APIKeySchema(ModelSchema):
    class Meta:
        model = APIKey
        fields = ['id', 'name', 'user', 'access_key']


class APIKeyCreatedSchema(APIKeySchema):
    secret_key: str

    @staticmethod
    def resolve_secret_key(obj):
        return obj.decrypt_secret_key()

class APIKeyCreateSchema(ModelSchema):
    user: Optional[int] = None  # auto-set from request.user

    class Meta:
        model = APIKey
        fields = ['name', 'user', 'access_key']
        optional_fields = ['access_key', 'user']
