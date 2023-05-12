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
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User
from src.utils import *
from src.models import User
from src.models import PickUpRequest
from datetime import datetime,timedelta
from django.contrib.auth import get_user_model
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


EMPLOYEE = 'Employee'
CUSTOMER = 'Customer'

@swagger_auto_schema(methods=['post'], tags=['Registraion abd Other customer Actions'],request_body=RegisterUserSerializer)
@api_view(["POST"])
def Register(request):
    data = request.data.copy()
    password = data.pop("password1", None)
    if password:
        data["password"] = password
    serializer = RegisterUserSerializer(data=data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()

    otp = generate_otp()

    user.email_otp = otp
    user.save()

    send_otp_email(user.email, otp)

    response_data = {
        "message": "Please check your email for the OTP to activate your account."
    }

    return Response(response_data)


@swagger_auto_schema(
    method='post',
    tags=['Registraion abd Other customer Actions'],
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'otp': openapi.Schema(type=openapi.TYPE_STRING)
        }
    ),
    responses={
        200: "{'message': 'Your account has been activated.'}",
        400: "{'error': 'OTP not provided.'} or {'error': 'Invalid OTP.'}",
        404: "{'error': 'User not found.'}"
    }
)
@api_view(["POST"])
def verify_email_otp(request, email):
    User = get_user_model()

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        response_data = {"error": "User not found."}
        return Response(response_data, status=status.HTTP_404_NOT_FOUND)

    otp = request.data.get('otp')

    if not otp:
        response_data = {"error": "OTP not provided."}
        return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

    if user.email_otp != otp:
        response_data = {"error": "Invalid OTP."}
        return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

    user.is_verified = True
    user.email_otp = ''
    user.save()

    response_data = {"message": "Your account has been activated."}
    return Response(response_data, status=status.HTTP_200_OK)


@swagger_auto_schema(methods=['post'], tags=['Registraion abd Other customer Actions'], request_body=AuthTokenSerializer)
@api_view(["POST"])
def login(request):
    serializer = AuthTokenSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.validated_data["user"]

    # Check if email OTP is verified
    if not user.is_verified:
        return Response({"message": "Email is not verified yet."})

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



# @swagger_auto_schema(methods=['post', 'get'], request_body=Client_ViewSerializer)
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def Client_View(request):
    user = request.user
    if user.is_staff:
        return Response({"message": "Get Authenticated First"})
    elif user.user_type != 'customer':
        return Response({"message": "Access Forbidden"})
    
    if request.method == 'POST':
        serializer = Client_ViewSerializer(data=request.data)
        if serializer.is_valid():
            client_view = serializer.save()
            client_view.cost_to_pay = client_view.calculate_price()
            client_view.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        client_views = ClientView.objects.all()
        serializer = Client_ViewSerializer(client_views, many=True)
        return Response(serializer.data)


# @swagger_auto_schema(methods=['get'], request_body=AuthTokenSerializer)

@swagger_auto_schema(methods=['post'], tags=['Registraion abd Other customer Actions'], request_body=ResetPasswordSerializer)
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


@swagger_auto_schema(
    methods=['put'],
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='Token in the format "Token <token>"'
        ),
    ],
    tags=['Registraion abd Other customer Actions'],
    request_body=UpdateUserSerializer)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def userupdate(request):
    email = request.user.email
    user = get_object_or_404(User, email=email)
    serializer = UpdateUserSerializer(user, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(methods=['put'], tags=['Registraion abd Other customer Actions'], request_body=UpdateUserLocationSerializer)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def userlocationupdate(request):
    user = get_object_or_404(User, pk=request.user.pk)
    serializer = UpdateUserLocationSerializer(user, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='delete',
    tags=['Registraion abd Other customer Actions'],
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='Token in the format "Token <token>"'
        ),
    ],
    operation_summary='Delete user',
    responses={
        204: 'User deleted successfully',
        401: 'Authentication credentials were not provided',
        404: 'User not found',
    },
    security=[{"Bearer": []}],
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def userdelete(request):
    user = get_object_or_404(User, pk=request.user.pk)
    user.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)

    

# Employee dashboard view to create a new client view
# @swagger_auto_schema(methods=['post'], request_body=Client_ViewSerializer)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_client_view(request):
    user = request.user
    if user.is_staff== True:
        return Response({"message": "Get Authenticated First"})
    elif user.user_type != 'employee':
        return Response({"message": "Access Forbidden"})
    else:
        serializer = Client_ViewSerializer(data=request.data)
        if serializer.is_valid():
            client_view = serializer.save()
            client_view.cost_to_pay = client_view.calculate_price()
            client_view.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# Employee dashboard view to get a specific client view by id
@swagger_auto_schema(
    method='get',
    tags=['Employee Actions'],
    operation_summary='Get client view by ID', 
    responses={
        200: Client_ViewSerializer(),
        404: 'Client view not found'
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_client_view(request, id):
    user = request.user
    if user.is_staff== True:
        return Response({"message": "Get Authenticated First"})
    elif user.user_type != 'employee':
        return Response({"message": "Access Forbidden"})
    else:
        try:
            client_view = ClientView.objects.get(id=id)
        except ClientView.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = Client_ViewSerializer(client_view)
        return Response(serializer.data)



@swagger_auto_schema(
    method='put',
    tags=['Employee Actions'],
    operation_summary='Update client view', 
    responses={
        200: 'Client view updated',
        400: 'Invalid input',
        404: 'Client view not found'
    },
    request_body=Client_ViewSerializer
)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_client_view(request, id):
    user = request.user
    if user.is_staff:
        return Response({"message": "Get Authenticated First"})
    elif user.user_type != 'employee':
        return Response({"message": "Access Forbidden"})
    else:
        try:
            client_view = ClientView.objects.get(id=id)
        except ClientView.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        # Add the email field to the request data
        request.data['email'] = user.email

        serializer = Client_ViewSerializer(client_view, data=request.data)
        if serializer.is_valid():
            client_view = serializer.save()
            client_view.cost_to_pay = client_view.calculate_price()
            client_view.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Employee dashboard view to delete a specific client view by id

@swagger_auto_schema(
    method='delete',
    tags=['client-views'],
    operation_summary='Delete client view',
    manual_parameters=[
        openapi.Parameter(
            'id',
            in_=openapi.IN_PATH,
            type=openapi.TYPE_INTEGER,
            required=True,
            description='ID of the client view to be deleted',
        ),
        openapi.Parameter(
            'Authorization',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='Token in the format "Token <token>"'
        ),
    ],
    responses={
        204: 'Client view deleted',
        404: 'Client view not found'
    }
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_client_view(request, id):
    user = request.user
    if user.is_staff== True:
        return Response({"message": "Get Authenticated First"})
    elif user.user_type != 'employee':
        return Response({"message": "Access Forbidden"})
    else:
        try:
            client_view = ClientView.objects.get(id=id)
        except ClientView.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        client_view.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)




@swagger_auto_schema(
    method='get',
    tags=['Employee Actions'],
    operation_summary='Generate report for all customers',
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='Token in the format "Token <token>"'
        ),
        openapi.Parameter(
            'user_type',
            in_=openapi.IN_QUERY,
            type=openapi.TYPE_STRING,
            required=False,
            description='Filter users by user_type (e.g. "customer")',
            enum=['customer'],
            default='customer'
        ),    ],
    responses={200: openapi.Response('Report data', schema=CustomerReportSerializer)}
)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def generate_report(request):
    test_param = request.query_params.get('test_param', None)
    user = request.user
    if user.is_staff == True:
        return Response({"message": "Get Authenticated First"})
    elif user.user_type != 'employee':
        return Response({"message": "Access Forbidden"})
    else:
        # Query the database for all users
        users = User.objects.filter(user_type='customer')

        # Generate the report
        report_data = {
            'start_date': None,
            'end_date': None,
            'total_users': users.count(),
            'userDetails': []
        }

        for user in users:
            user_dict = {
                'id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'user_type': user.user_type,
                'phone': user.phone_number,
                'province': user.province,
                'sector': user.sector,
                'cell': user.cell,
                'property_number': user.property_number,
                'gender': user.gender,
                'waste_type':user.waste_type  # Initialize an empty list for waste types
            }

            user_views = ClientView.objects.filter(user=user)
            if user_views:
                for view in user_views:
                    waste_type = view.waste_type
                    if waste_type not in user_dict['waste_type']:
                        user_dict['waste_type'].append(waste_type)  # Add the waste type to the list

            report_data['userDetails'].append(user_dict)

        return Response(report_data)




@swagger_auto_schema(
    method='post',tags=['Registraion abd Other customer Actions'],
    manual_parameters=[
        openapi.Parameter('user', openapi.IN_QUERY, description="User's email", type=openapi.TYPE_STRING),
        openapi.Parameter('month', openapi.IN_QUERY, description='Invoice month', type=openapi.TYPE_STRING),
        openapi.Parameter('payment_mode', openapi.IN_QUERY, description='Payment mode', type=openapi.TYPE_NUMBER),
        openapi.Parameter(
            'Authorization',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='Token in the format "Token <token>"'
        ),
    ]
)
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def invoice_view(request):
    if request.method == 'GET':
        invoices = Invoice.objects.all()
        serializer = InvoiceSerializer(invoices, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = InvoiceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@swagger_auto_schema(
    methods=['post'],
    request_body=PaymentSerializer,
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='Token in the format "Token <token>"'
        ),
    ]
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def payment_view(request):
    invoice = get_object_or_404(Invoice, id=request.data['invoice_id'], customer__user=request.user)
    if invoice.currentpayment == "PAID":
        return Response({'error': 'Invoice already paid.'}, status=status.HTTP_400_BAD_REQUEST)
    payment_serializer = PaymentSerializer(data=request.data)
    if payment_serializer.is_valid():
        payment = payment_serializer.save()
        otp_code = get_random_string(length=6, allowed_chars='0123456789')
        otp = OTP.objects.create(payment=payment, code=otp_code)
        otp_serializer = OTPSerializer(otp)
        return Response(otp_serializer.data, status=status.HTTP_201_CREATED)
    return Response(payment_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    methods=['post'],
    request_body=OTPSerializer,
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='Token in the format "Token <token>"'
        ),
    ]
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def otp_verify_view(request):
    otp_serializer = OTPSerializer(data=request.data)
    if otp_serializer.is_valid():
        otp = otp_serializer.save()
        if otp.is_valid():
            invoice = otp.payment.invoice
            invoice.currentpayment = "PAID"
            invoice.save()
            return Response({'status': 'Payment successful.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid OTP code.'}, status=status.HTTP_400_BAD_REQUEST)
    return Response(otp_serializer.errors, status=status.HTTP_400_BAD_REQUEST)




@swagger_auto_schema(
    methods=['post'],
    tags=['Registraion abd Other customer Actions'],
    request_body=PaymentSerializer,
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='Token in the format "Token <token>"'
        ),
    ]
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def RequestPickUp(request):
    """
    API view to allow a client to send a message to all employees in the company.
    """
    user = request.user
    if not user.is_authenticated:
        return Response({'error': 'User must be logged in.'}, status=status.HTTP_401_UNAUTHORIZED)
    if user.user_type != 'customer':
        return Response({'error': 'Access forbidden.'}, status=status.HTTP_403_FORBIDDEN)
    text = request.data.get('text')
    if not text:
        return Response({'error': 'Message text is required.'}, status=status.HTTP_400_BAD_REQUEST)
    email = user.email
    employees = User.objects.filter(is_staff=True)
    messages = []
    for employee in employees:
        message = PickUpRequest.objects.create(sender=user, email=email, text=text, to_all_employees=True)
        messages.append(message)
    serializer = RequestPickUpSerializer(messages, many=True)
    return Response(serializer.data)

@swagger_auto_schema(method='get', operation_description='Get a list of users')
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def all_my_request(request):
    user = request.user
    messages = PickUpRequest.objects.filter(sender=user)
    serializer = AllRequestPickUpSerializer(messages, many=True)
    return Response(serializer.data)

@swagger_auto_schema(
    methods=['post'],
    tags=['Employee Actions'],
    request_body=PaymentSerializer,
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='Token in the format "Token <token>"'
        ),
    ]
)
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def PickupRequestReceiving(request):
    """
    API view to list all pickup requests and allow employees to respond to them.
    """
    user = request.user
    if not user.is_authenticated:
        return Response({'error': 'User must be logged in.'}, status=status.HTTP_401_UNAUTHORIZED)
    if user.is_staff:
        return Response({'error': 'Access forbidden.'}, status=status.HTTP_403_FORBIDDEN)

    if request.method == 'GET':
        # Retrieve all pickup requests
        pickup_requests = PickUpRequest.objects.order_by('-timestamp')
        serializer = RequestPickUpSerializer(pickup_requests, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        # Create a new pickup request
        serializer = RequestPickUpSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
