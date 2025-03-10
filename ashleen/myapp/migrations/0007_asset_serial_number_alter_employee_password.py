# Generated by Django 5.1.1 on 2025-02-26 20:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0006_alter_employee_password'),
    ]

    operations = [
        migrations.AddField(
            model_name='asset',
            name='serial_number',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='employee',
            name='password',
            field=models.CharField(default='pbkdf2_sha256$870000$QM6gT0C9yP4BRYqCMB3wVt$qslVHoLi5Hk4k4F291H8JgzH0VgEWa3snTxC1COYmYo=', max_length=128),
        ),
    ]
