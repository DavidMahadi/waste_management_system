# Generated by Django 4.1.7 on 2023-05-15 09:38

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("src", "0005_rename_amount_payment_amount_to_pay_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="payment",
            name="user_full_name",
            field=models.CharField(blank=True, max_length=255),
        ),
    ]
