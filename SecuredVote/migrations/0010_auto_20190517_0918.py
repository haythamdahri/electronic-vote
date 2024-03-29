# Generated by Django 2.2.1 on 2019-05-17 09:18

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('SecuredVote', '0009_auto_20190517_0102'),
    ]

    operations = [
        migrations.AlterField(
            model_name='revision',
            name='pending',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SecuredVote.Pending'),
        ),
        migrations.AlterField(
            model_name='voter',
            name='private_key',
            field=models.FileField(max_length=1000, null=True, unique=True, upload_to=''),
        ),
        migrations.AlterField(
            model_name='voter',
            name='public_key',
            field=models.FileField(max_length=1000, null=True, unique=True, upload_to=''),
        ),
    ]
