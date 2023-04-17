from rest_framework import serializers,validators
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.models import User
from rest_framework import serializers
from .models import *
from django.contrib.auth.hashers import check_password

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.core.mail import send_mail
from rest_framework import serializers
from allauth.account.models import EmailConfirmation, EmailConfirmationHMAC
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView


class RegisterUserSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = (
            "first_name",
            "last_name",
            "email",
            "password1",
            "password2",
            "user_type",
            "phone_number",
            "second_number",
            "national_id",
            "province",
            "district",
            "sector",
            "cell",
            "property_number",
            "gender",
            "age",

        )
        extra_kwargs = {
            "first_name": {"required": True},
            "last_name": {"required": True},
            "email": {
                "required": True,
                "allow_blank": False,
                "validators": [
                    validators.UniqueValidator(
                        User.objects.all(), "User with this email already exists"
                    )
                ],
            },
            "user_type": {"required": True},
            "phone_number":{"required": True},
            "second_number":{"required": True},
            "national_id": {"required": True},
            "province": {"required": True},
            "district": {"required": True},
            "sector": {"required": True},
            "cell": {"required": True},
            "property_number": {"required": True},
            "gender": {"required": True},
            "age": {"required": True},
        }

    def validate(self, attrs):
        if attrs["password1"] != attrs["password2"]:
            raise serializers.ValidationError(
                {"password": "Password Fields didn't match"}
            )

        return attrs

    def create(self, validated_data):
        first_name = validated_data.get("first_name")
        last_name = validated_data.get("last_name")
        email = validated_data.get("email")
        user_type = validated_data.get("user_type")

        user = User.objects.create(
            username=email, first_name=first_name, last_name=last_name, email=email, user_type=user_type
        )

        user.set_password(validated_data["password1"])
        user.save()

        return user

class ResetPasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    password1 = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        if attrs["password1"] != attrs["password2"]:
            raise serializers.ValidationError(
                {"password": "Password Fields didn't match"}
            )
        return attrs

    def update(self, instance, validated_data):
        instance.set_password(validated_data["password1"])
        instance.save()
        return instance

    class Meta:
        model = User
        fields = ('old_password', 'password1', 'password2')


class VerifyEmailView(APIView):
    def get(self, request, *args, **kwargs):
        key = kwargs.get('key')
        email_confirmation = EmailConfirmation.objects.filter(key=key).first()
        if email_confirmation:
            email_address = email_confirmation.email_address
            email_address.verified = True
            email_address.user.is_active = True
            email_address.user.save()
            email_address.save()
            return Response({'detail': 'Email verified successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid verification key.'}, status=status.HTTP_400_BAD_REQUEST)




class PaymentSerializer(serializers.ModelSerializer):

    class Meta:
        model = Payment
        fields = ['id', 'user', 'waste_type', 'waste_quantity', 'amount', 'created_at', 'updated_at']


class WasteSerializer(serializers.ModelSerializer):

    class Meta:
        model = Waste
        fields = ['id', 'user', 'waste_type', 'quantity', 'waste_frequency', 'disposal_cost']


class SupportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Support
        fields = ['id', 'name', 'email', 'phone_number', 'message']
