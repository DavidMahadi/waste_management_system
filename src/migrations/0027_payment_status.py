# Generated by Django 4.1.7 on 2023-05-10 14:21

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("src", "0026_invoice_status"),
    ]

    operations = [
        migrations.AddField(
            model_name="payment",
            name="status",
            field=models.CharField(default="pending", max_length=20),
        ),
    ]
