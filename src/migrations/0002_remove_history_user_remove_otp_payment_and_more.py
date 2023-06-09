# Generated by Django 4.1.7 on 2023-05-18 06:10

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("src", "0001_initial"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="history",
            name="user",
        ),
        migrations.RemoveField(
            model_name="otp",
            name="payment",
        ),
        migrations.RemoveField(
            model_name="support",
            name="name",
        ),
        migrations.DeleteModel(
            name="WasteData",
        ),
        migrations.AlterField(
            model_name="payment",
            name="amount_to_pay",
            field=models.DecimalField(decimal_places=2, default=2000, max_digits=10),
        ),
        migrations.DeleteModel(
            name="History",
        ),
        migrations.DeleteModel(
            name="OTP",
        ),
        migrations.DeleteModel(
            name="Support",
        ),
    ]
