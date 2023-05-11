# Generated by Django 4.1.7 on 2023-05-02 06:02

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("src", "0004_rename_payment_client_view_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="WasteData",
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
                ("category", models.CharField(max_length=255)),
                ("amount", models.FloatField()),
            ],
        ),
        migrations.AddField(
            model_name="waste",
            name="date",
            field=models.DateField(auto_now=True),
        ),
        migrations.AlterField(
            model_name="client_view",
            name="cost_to_pay",
            field=models.DecimalField(
                blank=True, decimal_places=2, max_digits=10, null=True
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="gender",
            field=models.CharField(
                choices=[("male", "male"), ("female", "female"), ("others", "others")],
                default="male",
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="user_type",
            field=models.CharField(
                choices=[("customer", "customer"), ("employee", "employee")],
                default="customer",
                max_length=200,
            ),
        ),
    ]