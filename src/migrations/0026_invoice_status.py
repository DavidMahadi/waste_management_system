# Generated by Django 4.1.7 on 2023-05-10 14:09

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("src", "0025_payment_otp"),
    ]

    operations = [
        migrations.AddField(
            model_name="invoice",
            name="status",
            field=models.CharField(default="pending", max_length=20),
        ),
    ]
