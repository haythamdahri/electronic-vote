# Generated by Django 2.2.1 on 2019-05-16 15:29

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('SecuredVote', '0003_auto_20190516_0152'),
    ]

    operations = [
        migrations.AddField(
            model_name='voter',
            name='birth_date',
            field=models.DateTimeField(default=django.utils.timezone.now, null=True),
        ),
    ]