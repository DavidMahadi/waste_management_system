import random
from django.conf import settings
from django.core.mail import send_mail


def generate_otp():
    # Generate a list of 6 random digits
    digits = [random.randint(0, 9) for _ in range(5)]
    
    # Convert the digits to a string and return
    return ''.join(map(str, digits))


def send_otp_email(email,otp):
    try:
        subject = 'Test email'
        message = f'This is a test email from Django, this is OTP {otp}'
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]
        send_mail(subject, message, from_email, recipient_list, fail_silently=False)
    except Exception as e:
        print(e)
        return False
    return True


