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
    path('Registration', Register, name='Registration'),
    path('login', login, name='login'),
    path('reset_password', reset_password, name='reset-password'),
    path('logout', knox_views.LogoutView.as_view(), name='logout'),
    path('logoutall', knox_views.LogoutAllView.as_view(), name='logoutall'),
    path('generate_otp', generate_otp, name='generate_otp'),
    path('verify_email_otp/<str:email>', verify_email_otp, name='verify_email_otp'),
    path('userupdate', userupdate, name='userupdate'),
    path('userlocationupdate', userlocationupdate, name='userlocationupdate'),
    path('userdelete', userdelete, name='userdelete'),
    path('invoiceview', invoice_view, name='invoiceview'),
    path('createpayment', create_payment, name='createpayment'),
    path('submitpaymentinfo', submit_payment_info, name='submitpaymentinfo'),
    path('otp-verify', otp_verify_view, name='otp_verify'),

# employee dashboard


    path('createclientview', create_client_view, name='createclientview'),
    path('getclient_view', get_client_view, name='getclient_view'),
    path('updateclientview', update_client_view, name='updateclientview'),
    path('deleteclientview', delete_client_view, name='deleteclientview'),
    path('generatereport', generate_report, name='generatereport'),
    path('requestpickup', RequestPickUp, name='requestpickup'),
    path('PickupRequestReceiving', PickupRequestReceiving, name='PickupRequestReceiving'),
    path('all_mypickup_request', all_my_request, name='all_mypickup_request'),
    




    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc')
]



# Swagger Documentation

urlpatterns += [
   re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
   re_path(r'^swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
   re_path(r'^redoc/$', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
