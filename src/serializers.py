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


from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

User = get_user_model()

class RegisterUserSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    
    class Meta:
        model = User
        fields = (
            "full_name",
            "email",
            "password",
            "user_type",
            "phone_number",
            "province",
            "district",
            "sector",
            "cell",
            "property_number",
        )
        extra_kwargs = {
            "full_name": {"required": True,"allow_blank": True,},
            "email": {
                "required": True,
                "allow_blank": False,
            },
            "user_type": {"required": True},
            "phone_number": {"required": True},
            "province": {"required": True},
            "district": {"required": True},
            "sector": {"required": True},
            "cell": {"required": True},
            "property_number": {"required": True},
        }

        def validate(self, attrs):
            full_name = attrs["full_name"]
            first_name, _, last_name = full_name.partition(" ")
            if not last_name:
                raise serializers.ValidationError({"full_name": "Last name is required."})
            attrs["first_name"] = first_name
            attrs["last_name"] = last_name

            password = attrs.get('password')
            if not password:
                raise serializers.ValidationError({"password": "Password is required."})
            attrs.pop('password')

            user = User(**attrs)
            user.set_password(password)

            attrs['password1'] = password
            attrs['password2'] = password

            return attrs
        
        def create(self, validated_data):
            email = validated_data.get('email')
            username = email
            validated_data['username'] = username
            user = super().create(validated_data)
            return user


    def create(self, validated_data):
        email = validated_data.get('email', None)
        username = email
        if email and User.objects.filter(email=email).exists():
            raise ValidationError(_('Email addresses must be unique.'))
        user = User.objects.create_user(username=username, **validated_data)
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



class CustomerReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerReport
        fields = ('id', 'start_date', 'end_date', 'total_users', 'userDetails')


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = ['user', 'month', 'payment_mode', 'status']




class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ('id', 'invoice', 'amount', 'payment_date', 'status')
        read_only_fields = ('id', 'payment_date', 'status')


class OTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = OTP
        fields = '__all__'





class RequestPickUpSerializer(serializers.ModelSerializer):
    class Meta:
        model = PickUpRequest
        fields = ('id','email','timestamp', 'text', )


class AllRequestPickUpSerializer(serializers.ModelSerializer):
    class Meta:
        model = PickUpRequest
        fields = '__all__'
