from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from django.core.validators import FileExtensionValidator
from rest_framework.generics import get_object_or_404
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import AccessToken

from shered.utility import check_email_or_phone, send_email, send_phone_code, check_user_type
from .models import User, UserConfirmation, VIA_EMAIL, VIA_PHONE, NEW, CODE_VERIFIED, DONE, PHOTO_DONE
from rest_framework import exceptions
from django.db.models import Q
from rest_framework import serializers
from rest_framework.exceptions import ValidationError, PermissionDenied, NotFound


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = (
            'id',
            'auth_type',
            'auth_status'
        )
        extra_kwargs = {
            'auth_type': {'read_only': True, 'required': False},
            'auth_status': {'read_only': True, 'required': False}
        }

    def create(self, validated_data):
        print(validated_data)
        user = super(SignUpSerializer, self).create(validated_data)
        print(user, 'user')
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone_number, code)
            # send_phone_code(user.phone_number, code)
        user.save()
        return user

    def validate(self, data):
        super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        return data

    @staticmethod
    def auth_validate(data):
        user_input = str(data.get('email_phone_number')).lower()  # =9998998090816, fozilov@gmail.com
        input_type = check_email_or_phone(user_input)  # email or phone
        if input_type == "email":
            data = {
                "email": user_input,
                "auth_type": VIA_EMAIL
            }
        elif input_type == "phone":
            data = {
                "phone_number": user_input,
                "auth_type": VIA_PHONE
            }
        else:
            data = {
                'success': False,
                'message': "You must send email or phone number"
            }
            raise ValidationError(data)

        return data

    def validate_email_phone_number(self, value):
        value = value.lower()
        if value and User.objects.filter(email=value).exists():
            data = {
                "success": False,
                "message": "Bu email allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)
        elif value and User.objects.filter(phone_number=value).exists():
            data = {
                "success": False,
                "message": "Bu telefon raqami allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)

        return value

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        print(data)

        data.update(instance.token())

        print(data)

        return data


class ChangeUserInformationSerializer(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=False)
    last_name = serializers.CharField(write_only=True, required=False)
    username = serializers.CharField(write_only=True, required=False)
    password = serializers.CharField(write_only=True, required=False)
    confirm_password = serializers.CharField(write_only=True, required=False)

    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)

        if password != confirm_password:
            raise ValidationError({
                'message': 'password and confirm_password do not match'
            })

        if password:
            validate_password(password)

        return data

    def validate_username(self, username):

        if User.objects.filter(username=username).exists():
            raise ValidationError({
                'message': 'username already exists'
            })

        if len(username) < 5 or len(username) > 15:
            raise ValidationError({
                'message': 'username must be between 5 and 15 characters'
            })
        if str(username).isdigit():
            raise ValidationError({
                'message': 'username must be not digits'
            })

        return username

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.username = validated_data.get('username', instance.username)
        instance.password = validated_data.get('password', instance.password)

        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))

        if instance.auth_status == CODE_VERIFIED:
            instance.auth_status = DONE
        instance.save()
        return instance


class ChangeUserPhotoSerializer(serializers.Serializer):
    photo = serializers.ImageField(validators=[FileExtensionValidator(allowed_extensions=[
        'jpg', 'jpeg', 'png'
    ])])

    def update(self, instance, validated_data):
        photo = validated_data.get('photo')
        if photo:
            instance.photo = photo
            instance.auth_status = PHOTO_DONE
            instance.save()
        return instance


class ForgetPasswordSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        email_or_phone = data.get('email_or_phone', None)

        if email_or_phone is None:
            raise ValidationError({
                'message': 'Email or phone number berishingiz shart'
            })

        user = User.objects.filter(Q(phone_number=email_or_phone) | Q(email=email_or_phone))

        if not user.exists():
            raise ValidationError({
                'message': 'User mavjud emas'
            })
        data['user'] = user.first()

        return data


class ResetPasswordSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    password = serializers.CharField(min_length=8, required=True, write_only=True)
    confirm_password = serializers.CharField(min_length=8, required=True, write_only=True)
    old_password = serializers.CharField(min_length=8, required=True, write_only=True)

    # def __init__(self, *args, **kwargs):
    #     super(ResetPasswordSerializer, self).__init__(*args, **kwargs)
    #     self.fields['old_password'] = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = User
        fields = (
            'id',
            'password',
            'confirm_password',
            'old_password'
        )

    def validate(self, data):
        user = self.instance
        old_password = data.get('old_password')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if not user.check_password(old_password):
            raise serializers.ValidationError({
                'success': False,
                'message': "Eski parol noto‘g‘ri"
            })

        if password != confirm_password:
            raise serializers.ValidationError({
                'success': False,
                'message': "Yangi parollar bir-biriga mos kelmadi"
            })

        validate_password(password)
        return data

    def update(self, instance, validated_data):
        instance.set_password(validated_data['password'])
        instance.save()
        return instance


# User = get_user_model()
#
#
# class LoginSerializer(serializers.Serializer):
#     userinput = serializers.CharField(required=True)
#     password = serializers.CharField(write_only=True)
#
#     def validate(self, data):
#         user_input = data.get('userinput')
#         password = data.get('password')
#
#         user = self.get_user(user_input)
#         if not user:
#             raise ValidationError({"message": "No active account found"})
#
#         if user.auth_status in [NEW, CODE_VERIFIED]:
#             raise ValidationError({"message": "Siz ro‘yxatdan to‘liq o‘tmagansiz!"})
#
#         authenticated_user = authenticate(username=user.username, password=password)
#         if not authenticated_user:
#             raise ValidationError({"message": "Login yoki parol noto‘g‘ri"})
#
#
#         return {
#             "token": user.token(),
#             "auth_status": user.auth_status,
#             "full_name": user.full_name,
#         }
#
#     def get_user(self, user_input):
#
#         if "@" in user_input:
#             return User.objects.filter(email__iexact=user_input).first()
#         elif user_input.isdigit():
#             return User.objects.filter(phone_number=user_input).first()
#         else:
#             return User.objects.filter(username__iexact=user_input).first()


class LoginSerializer(TokenObtainPairSerializer):

    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['userinput'] = serializers.CharField(required=True)
        self.fields['username'] = serializers.CharField(required=False, read_only=True)

    def auth_validate(self, data):
        user_input = data.get('userinput', None)
        if check_user_type(user_input) == 'username':
            username = user_input
        elif check_user_type(user_input) == "email":
            user = self.get_user(email__iexact=user_input) # Fozilov, fozilov
            username = user.username
        elif check_user_type(user_input) == 'phone':
            user = self.get_user(phone_number=user_input)
            username = user.username
        else:
            data = {
                'success': False,
                'message': "Siz email, username yoki telefon raqami jonatishingiz kerak"
            }
            raise ValidationError(data)

        authentication_kwargs = {
            self.username_field: username,
            'password': data['password']
        }

        current_user = User.objects.filter(username__iexact=username).first()  # None

        if current_user is not None and current_user.auth_status in [NEW, CODE_VERIFIED]:
            raise ValidationError(
                {
                    'success': False,
                    'message': "Siz royhatdan toliq otmagansiz!"
                }
            )
        user = authenticate(**authentication_kwargs)
        if user is not None:
            self.user = user
        else:
            raise ValidationError(
                {
                    'success': False,
                    'message': "Sorry, login or password you entered is incorrect. Please check and trg again!"
                }
            )

    def validate(self, data):
        self.auth_validate(data)
        if self.user.auth_status not in [DONE, PHOTO_DONE]:
            raise PermissionDenied("Siz login qila olmaysiz. Ruxsatingiz yoq")
        data = self.user.token()
        data['auth_status'] = self.user.auth_status
        data['full_name'] = self.user.full_name
        return data

    def get_user(self, **kwargs):
        users = User.objects.filter(**kwargs)
        if not users.exists():
            raise ValidationError(
                {
                    "message": "No active account found"
                }
            )
        return users.first()


class LoginRefreshTokenSerializer(TokenRefreshSerializer):

    def validate(self, attrs):
        data = super(LoginRefreshTokenSerializer, self).validate(attrs)
        access_token = AccessToken(data['access'])
        user_id = access_token['user_id']
        user = get_object_or_404(User, id=user_id)
        update_last_login(None, user)

        return data


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(required=True)
