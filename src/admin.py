from django.contrib import admin
from .models import *
# Register your models here.
admin.site.register(User),
admin.site.register(ClientView),
admin.site.register(UpdateProfile),
admin.site.register(UpdateLocationProfile),
admin.site.register(History),
admin.site.register(CustomerReport),
admin.site.register(Invoice),
admin.site.register(Payment),
admin.site.register(OTP),

