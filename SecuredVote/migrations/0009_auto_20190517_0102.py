# Generated by Django 2.2.1 on 2019-05-17 01:02

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('SecuredVote', '0008_auto_20190517_0054'),
    ]

    operations = [
        migrations.AddField(
            model_name='pending',
            name='done',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='revision',
            name='done',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='revision',
            name='pending',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SecuredVote.Pending'),
        ),
    ]
