# Generated by Django 4.1.7 on 2023-05-09 14:29

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("src", "0018_user_waste_type_alter_clientview_waste_type"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="clientview",
            name="waste_type",
        ),
    ]
