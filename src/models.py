from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
from django.conf import settings

# Create your models here.


class User(AbstractUser):
    USER_TYPE_CHOICES = (
        ("customer", "customer"),
        ("employee", "employee"),
    )

    USER_GENDER = (
        ("male",'male'),
        ("female",'female'),
        ("others",'others'),
    )
    user_type = models.CharField(max_length=200, choices=USER_TYPE_CHOICES, default="customer")
    phone_number = models.CharField(max_length=200, null=True, blank=True)
    province = models.CharField(max_length=200, null=True, blank=True)
    district = models.CharField(max_length=200, null=True, blank=True)
    sector = models.CharField(max_length=200, null=True, blank=True)
    cell = models.CharField(max_length=200, null=True, blank=True)
    property_number = models.CharField(max_length=200, null=True, blank=True)
    gender = models.CharField(max_length=200, choices=USER_GENDER, default='male')
    age = models.IntegerField(null=True)
    is_verified=models.BooleanField(default=False)
    email_otp=models.CharField(max_length=500, blank=True)

    def __str__(self):
        return self.first_name +'  '+  self.user_type



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


 
