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
            "province",
            "district",
            "sector",
            "cell",
            "property_number",
            "gender",
            
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
            "province": {"required": True},
            "district": {"required": True},
            "sector": {"required": True},
            "cell": {"required": True},
            "property_number": {"required": True},
            "gender": {"required": True},
            
            
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



class UpdateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UpdateProfile
        fields = (
            "first_name",
            "last_name",
            "email",
            "phone_number",
         
            
        )
        extra_kwargs = {
            "first_name": {"required": True},
            "last_name": {"required": True},
            "email": {"required": True},
            "phone_number":{"required": True},
            
            
        }

    def validate(self, data):
        email = data.get("email")
        if email and email != self.instance.email:
            # If the email address is being changed, update the username field as well
            username = email
            data["username"] = username
        return data


class UpdateUserLocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UpdateLocationProfile
        fields = (
            "property_number",
            "province",
            "district",
            "sector",
            "cell",
         
            
        )
        extra_kwargs = {
           "property_number":{"required": True},
            "province": {"required": True},
            "district": {"required": True},
            "sector": {"required": True},
            "cell": {"required": True},

            }

    def validate(self, data):
        email = data.get("email")
        if email and email != self.instance.email:
            # If the email address is being changed, update the username field as well
            username = email
            data["username"] = username
        return data


class Client_ViewSerializer(serializers.ModelSerializer):
    cost_to_pay = serializers.SerializerMethodField()

    def get_cost_to_pay(self, obj):
        return obj.calculate_price()

    class Meta:
        model = ClientView
        fields = ['id', 'user', 'waste_type', 'waste_quantity', 'cost_to_pay', 'created_at', 'updated_at']



class WasteSerializer(serializers.ModelSerializer):

    class Meta:
        model = Waste
        fields = ['id', 'user', 'waste_type', 'quantity', 'waste_frequency', 'disposal_cost']


class SupportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Support
        fields = ['id', 'name', 'email', 'phone_number', 'message']



