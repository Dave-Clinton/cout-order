# Generated by Django 5.0.7 on 2024-08-06 07:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0015_alter_affidavit_content'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='deposit_paid',
            field=models.CharField(blank=True, max_length=40, null=True),
        ),
        migrations.AlterField(
            model_name='profile',
            name='monthly_rent',
            field=models.CharField(blank=True, max_length=40, null=True),
        ),
        migrations.AlterField(
            model_name='profile',
            name='year_of_entry',
            field=models.CharField(blank=True, max_length=40, null=True),
        ),
    ]