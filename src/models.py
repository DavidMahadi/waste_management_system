from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser,PermissionsMixin
from django.utils.translation import gettext as _
from django.contrib.auth import get_user_model
from django.conf import settings

# Create your models here.


class User(AbstractUser, PermissionsMixin):
    # remove the username field
    email = models.EmailField(_('email address'), unique=True)
    
    USER_TYPE_CHOICES = (
        ("customer", "customer"),
        ("employee", "employee"),
    )

    USER_GENDER = (
        ("male",'male'),
        ("female",'female'),
        ("others",'others'),
    )
    full_name = models.CharField(max_length=255, blank=True)
    user_type = models.CharField(max_length=200, choices=USER_TYPE_CHOICES, default="customer")
    phone_number = models.CharField(max_length=200, null=True, blank=False)
    province = models.CharField(max_length=200, null=True, blank=False)
    district = models.CharField(max_length=200, null=True, blank=False)
    sector = models.CharField(max_length=200, null=True, blank=False)
    cell = models.CharField(max_length=200, null=True, blank=False)
    property_number = models.CharField(max_length=200, null=True, blank=False)
    is_verified=models.BooleanField(default=False)
    email_otp=models.CharField(max_length=500, blank=True)

    def save(self, *args, **kwargs):
        if not self.full_name.strip() and self.first_name.strip() and self.last_name.strip():
            self.full_name = f"{self.first_name} {self.last_name}".strip()

        super().save(*args, **kwargs)

    def __str__(self):
        return self.full_name +' ' + self.user_type




class ClientView(models.Model):
    WASTE_TYPE_CHOICES = (
        ("Organic waste",'Organic waste'),
        ("In Organic waste",'In Organic waste'),
        ("Chemical waste",'Chemical waste'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments')
    waste_type = models.CharField(max_length=200, choices=WASTE_TYPE_CHOICES, default='Organic waste')
    waste_quantity = models.IntegerField()
    cost_to_pay = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.waste_type

    def calculate_price(self):
        if self.waste_type == 'Organic waste':
            price_per_unit = 2000
        elif self.waste_type == 'In Organic waste':
            price_per_unit = 3500
        elif self.waste_type == 'Chemical waste':
            price_per_unit = 5000
        else:
            # Handle invalid waste_type values
            raise ValueError('Invalid waste_type value')

        total_price = price_per_unit * self.waste_quantity
        return total_price

    def save(self, *args, **kwargs):
        if not self.cost_to_pay:
            # Calculate the cost_to_pay if it hasn't been set yet
            self.cost_to_pay = self.calculate_price()
        super().save(*args, **kwargs)





class UpdateProfile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=200, null=True, blank=True)
    last_name = models.CharField(max_length=200, null=True, blank=True)
    email = models.EmailField(max_length=200, null=True, blank=True)
    phone_number = models.CharField(max_length=200, null=True, blank=True)


    def __str__(self):
        return self.first_name


class UpdateLocationProfile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    province = models.CharField(max_length=200, null=True, blank=True)
    district = models.CharField(max_length=200, null=True, blank=True)
    sector = models.CharField(max_length=200, null=True, blank=True)
    cell = models.CharField(max_length=200, null=True, blank=True)
    property_number = models.CharField(max_length=200, null=True, blank=True)

    def __str__(self):
        return self.first_name


class Waste(models.Model):
    WASTE_TYPE_CHOICES = (
        ("Organic waste",'Organic waste'),
        ("In Organic waste",'In Organic waste'),
        ("Chemical waste",'Chemical waste'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    waste_type = models.CharField(max_length=100, choices=WASTE_TYPE_CHOICES)
    date = models.DateField(auto_now=True)
    quantity = models.DecimalField(max_digits=10, decimal_places=2)
    waste_frequency = models.IntegerField()
    disposal_cost = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return str(self.user)


class WasteData(models.Model):
    
    category = models.CharField(max_length=255)
    amount = models.FloatField()

class Support(models.Model):
    name = models.ForeignKey(User, on_delete=models.CASCADE)
    email = models.EmailField()
    phone_number = models.CharField(max_length=20)
    message = models.TextField()

    def __str__(self):
        return str(self.name)


class History(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)




class CustomerReport(models.Model):
    start_date = models.DateTimeField(auto_now_add=True)
    end_date = models.DateTimeField(null=True)
    total_users = models.IntegerField()
    userDetails = models.JSONField()




class Invoice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    month = models.TextField()
    payment_mode = models.DecimalField(max_digits=8, decimal_places=2)
    currentpayment = models.CharField(max_length=40)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default='pending')


    

class Payment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,default=1)
    month = models.DateField(default=timezone.now)
    amount_to_pay = models.DecimalField(max_digits=8, decimal_places=2)
    payment_date = models.DateTimeField(default=timezone.now)
    is_confirmed = models.BooleanField(default=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.full_name = f"{self.user.first_name} {self.user.last_name}"



class PaymentInfo(models.Model):
    payment = models.ForeignKey(Payment, on_delete=models.CASCADE)
    payment_mode = models.CharField(max_length=50)
    payment_number = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)






class OTP(models.Model):
    payment = models.ForeignKey(Payment, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        return (timezone.now() - self.created_at).seconds < 600  # OTP valid for 10 minutes





class PickUpRequest(models.Model):
    sender = models.ForeignKey(User, related_name='sent_messages', on_delete=models.CASCADE)
    email = models.CharField(max_length=255)
    text = models.TextField()
    to_all_employees = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.sender.username} ({self.email}) sent a message at {self.timestamp}'

