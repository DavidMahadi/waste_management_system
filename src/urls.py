from django.contrib import admin
from django.urls import path, include
from knox import views as knox_views
from .views import *



urlpatterns = [
    path('register_employee', Employee_register, name='register_employee'),
    path('register_customer', Customer_register, name='register_customer'),
    path('login', login, name='login'),
    path('customer', customer_view, name='customer-view'),
    path('employee', employee_view, name='employee-view'),
    path('reset-password/', reset_password, name='reset-password'),
    path('logout', knox_views.LogoutView.as_view(), name='logout'),
    path('logoutall', knox_views.LogoutAllView.as_view(), name='logoutall'),
]
