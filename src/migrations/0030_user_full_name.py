# Generated by Django 4.1.7 on 2023-05-11 06:36

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("src", "0029_remove_user_waste_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="full_name",
            field=models.CharField(blank=True, max_length=255),
        ),
    ]