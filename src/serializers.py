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

from django.contrib.auth import get_user_model
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
User = get_user_model()

class RegisterUserSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(required=True, min_length=3)
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
            "full_name": {"required": True},
            "email": {"required": True, "allow_blank": True},
            "user_type": {"required": False},  # Optional field
            "phone_number": {"required": True},  # Optional field
            "province": {"required": True},  # Optional field
            "district": {"required": True},  # Optional field
            "sector": {"required": True},  # Optional field
            "cell": {"required": True},  # Optional field
            "property_number": {"required": True},  # Optional field
        }

    def validate_full_name(self, value):
        names = value.split()
        if len(names) < 2:
            raise serializers.ValidationError("Lastname is required")
        return value

    def validate(self, attrs):
        full_name = attrs["full_name"]
        first_name, _, last_name = full_name.partition(" ")
        if not last_name:
            raise serializers.ValidationError({"full_name": "Last name is required."})
        attrs["first_name"] = first_name
        attrs["last_name"] = last_name

        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password')
        email = validated_data.pop('email')
        username = email
        first_name = validated_data.pop('first_name')  # Retrieve the first_name from validated_data
        last_name = validated_data.pop('last_name')  # Retrieve the last_name from validated_data

        # Create the user with the retrieved values
        user = User.objects.create_user(username=username, email=email, password=password,
                                        first_name=first_name, last_name=last_name, **validated_data)
        
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
    full_name = serializers.CharField(required=True, min_length=3)

    class Meta:
        model = UpdateProfile
        fields = (
            "full_name",
            "email",
            "phone_number",
        )
        extra_kwargs = {
            "email": {"required": True},
            "phone_number": {"required": True},
        }

    def validate_full_name(self, value):
        names = value.split()
        if len(names) < 2:
            raise serializers.ValidationError("Full name should include at least first name and last name.")
        return value

    def validate(self, data):
        full_name = data.get("full_name")
        if full_name:
            names = full_name.split()
            if len(names) >= 2:
                first_name = names[0]
                last_name = ' '.join(names[1:])
                data["first_name"] = first_name
                data["last_name"] = last_name
            else:
                data["first_name"] = names[0]
                data["last_name"] = ""
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



class CustomerReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerReport
        fields = ('id', 'start_date', 'end_date', 'total_users', 'userDetails')


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = ['user', 'month', 'payment_mode', 'status']



class PaymentSerializer(serializers.ModelSerializer):
    full_name = serializers.ReadOnlyField(source='user.get_full_name')

    class Meta:
        model = CreatePayment
        fields = ['id', 'full_name', 'month', 'amount_to_pay', 'payment_date']
        read_only_fields = ['id', 'month', 'amount_to_pay', 'payment_date']

    def create(self, validated_data):
        user = self.context['request'].user
        month = timezone.now().date().replace(day=1) # set the day to 1st of current month
        amount_to_pay = validated_data.get('amount_to_pay', 2000) # default amount to pay per month
        payment = Payment(user=user, month=month, amount_to_pay=amount_to_pay)
        payment.save()
        return payment

class ConfirmingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConfirmingPayment
        fields = ['amount','payment_mode', 'phone_number']


class RequestPickUpSerializer(serializers.ModelSerializer):
    class Meta:
        model = PickUpRequest
        fields = ('id','email','timestamp', 'text', )


class AllRequestPickUpSerializer(serializers.ModelSerializer):
    class Meta:
        model = PickUpRequest
        fields = '__all__'
