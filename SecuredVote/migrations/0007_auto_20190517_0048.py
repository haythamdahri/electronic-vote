# Generated by Django 2.2.1 on 2019-05-17 00:48

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('SecuredVote', '0006_auto_20190516_1606'),
    ]

    operations = [
        migrations.CreateModel(
            name='pending',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file', models.FileField(upload_to='')),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.RemoveField(
            model_name='vote',
            name='file',
        ),
    ]
