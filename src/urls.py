from django.contrib import admin
from django.urls import path, include, re_path
from knox import views as knox_views
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from src.views import *
from src.utils import generate_otp


schema_view = get_schema_view(
   openapi.Info(
      title="waste_management_system",
      default_version='v1',
      description="Test description",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
)

# Project Urls

urlpatterns = [
    path('register_employee', Employee_register, name='register_employee'),
    path('register_customer', Customer_register, name='register_customer'),
    path('login', login, name='login'),
    path('customer', customer_view, name='customer-view'),
    path('employee', employee_view, name='employee-view'),
    path('reset_password', reset_password, name='reset-password'),
    path('logout', knox_views.LogoutView.as_view(), name='logout'),
    path('logoutall', knox_views.LogoutAllView.as_view(), name='logoutall'),
    path('generate_otp', generate_otp, name='generate_otp'),
    path('verify_email_otp/<str:email>/', verify_email_otp, name='verify_email_otp'),


    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc')
]



# Swagger Documentation

urlpatterns += [
   re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
   re_path(r'^swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
   re_path(r'^redoc/$', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
