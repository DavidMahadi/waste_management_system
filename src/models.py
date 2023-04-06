from django.db import models
from django.contrib.auth.models import AbstractUser, User

# Create your models here.


class User(AbstractUser):
    AUTH_USER_MODEL = 'src.User'
    USER_TYPE_CHOICES = (
        ("Customer", "Customer"),
        ("Employee", "Employee"),
    )

    gender = (
        ("Male",'Male'),
        ("Female",'Female'),
        ("Others",'Others'),
    )

    user_type = models.CharField(max_length=200,choices=USER_TYPE_CHOICES, default="CUSTOMER")
    phone_number = models.CharField(max_length=200,default="")
    second_number = models.CharField(max_length=200,default="")
    national_id = models.CharField(max_length=200,default="")
    province = models.CharField(max_length=200,default="")
    district = models.CharField(max_length=200,default="")
    sector = models.CharField(max_length=200,default="")
    cell = models.CharField(max_length=200,default="")
    property_number = models.CharField(max_length=200, default="")
    gender = models.CharField(max_length=200,choices=gender, default=1)
    age = models.IntegerField(default=1)

    def __str__(self):
        return self.first_name +'  '+  self.user_type
