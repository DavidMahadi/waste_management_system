# Generated by Django 4.1.7 on 2023-05-10 10:18

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("src", "0022_alter_user_waste_type"),
    ]

    operations = [
        migrations.CreateModel(
            name="CustomerReport",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("start_date", models.DateTimeField(auto_now_add=True)),
                ("end_date", models.DateTimeField(null=True)),
                ("total_users", models.IntegerField()),
                ("userDetails", models.JSONField()),
            ],
        ),
        migrations.DeleteModel(
            name="Report",
        ),
    ]
