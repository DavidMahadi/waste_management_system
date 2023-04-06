from django.http import JsonResponse
from .models import *
from rest_framework.permissions import IsAuthenticated
from .serializers import *
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from knox.auth import AuthToken
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User


EMPLOYEE = 'Employee'
CUSTOMER = 'Customer'

@api_view(["POST"])
def Employee_register(request):
    user_type = request.data.get("user_type", None)
    serializer = RegisterUserSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()

    _, token = AuthToken.objects.create(user)

    current_user = serializer.instance
    if current_user.user_type == EMPLOYEE:
        current_user.is_staff = True
        current_user.save()

    return Response(
        {
            "user_infos": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            },
            "message": "Account Created Successfully.",
        }
    )


@api_view(["POST"])
def Customer_register(request):
    user_type = request.data.get("user_type", None)
    serializer = RegisterUserSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()

    _, token = AuthToken.objects.create(user)

    current_user = serializer.instance
    if current_user.user_type == CUSTOMER:
        current_user.is_staff=False
        current_user.save()

    return Response(
        {
            "user_infos": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            },
            "message": "Account Created Successfully.",
        }
    )


@api_view(["POST"])
def login(request):
    serializer = AuthTokenSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.validated_data["user"]

    _, token = AuthToken.objects.create(user)

    return Response(
        {
            "user_info": {
                "id": user.id,
                "username": user.username,
            },
            "token": token,
        }
    )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def customer_view(request):
    # Your view code here
    return Response({'message': 'Hello, Client View!'})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def employee_view(request):
    if request.user.is_staff != True:
            return Response({"message": "Get Authenticated First"})
    # Your view code here
    return Response({'message': 'Hello, Employee View!'})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reset_password(request):
    user = request.user
    serializer = ResetPasswordSerializer(data=request.data)
    if serializer.is_valid():
        # Check the old password
        if user.check_password(serializer.validated_data['old_password']):
            # Set the new password
            user.set_password(serializer.validated_data['password1'])
            user.save()
            return Response({'message': 'Password reset successful.'})
        else:
            return Response({'error': 'Incorrect old password.'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    try:
        auth_token = AuthToken.objects.get(user=user)
    except AuthToken.DoesNotExist:
        return Response(status=status.HTTP_401_UNAUTHORIZED)

    new_password = request.data.get('new_password')
    confirm_password = request.data.get('confirm_password')
    if new_password != confirm_password:
        return Response({'detail': 'New password and confirm password do not match.'}, status=status.HTTP_400_BAD_REQUEST)

    user.set_password(new_password)
    user.save()

    # delete existing auth token
    auth_token.delete()

    # create new auth token
    new_auth_token = AuthToken.objects.create(user=user)
    
    return Response({'detail': 'Password reset successful.', 'token': new_auth_token.token}, status=status.HTTP_200_OK)