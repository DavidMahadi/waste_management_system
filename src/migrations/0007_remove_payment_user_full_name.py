# Generated by Django 4.1.7 on 2023-05-15 09:56

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("src", "0006_payment_user_full_name"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="payment",
            name="user_full_name",
        ),
    ]