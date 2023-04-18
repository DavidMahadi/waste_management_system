import random
from django.core.mail import send_mail
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view


@api_view(['POST'])
def generate_otp(request):
    """Generate a six-digit OTP and send it to user's email"""
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

    digits = "0123456789"
    otp = ""
    for i in range(6):
        otp += random.choice(digits)

    # Send the OTP to the user's email
    send_mail(
        subject='Your OTP for email verification',
        message=f'Your OTP is: {otp}',
        from_email='badmannkr@example.com',
        recipient_list=[email],
        fail_silently=False,
    )

    return Response({'message': 'OTP has been sent to your email.'})