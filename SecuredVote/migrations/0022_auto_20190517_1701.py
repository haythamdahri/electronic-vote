# Generated by Django 2.2.1 on 2019-05-17 17:01

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('SecuredVote', '0021_auto_20190517_1324'),
    ]

    operations = [
        migrations.AddField(
            model_name='revision',
            name='is_valid',
            field=models.BooleanField(default=None),
        ),
        migrations.AlterField(
            model_name='revision',
            name='pending',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SecuredVote.Pending'),
        ),
    ]
