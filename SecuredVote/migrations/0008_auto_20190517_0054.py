# Generated by Django 2.2.1 on 2019-05-17 00:54

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('SecuredVote', '0007_auto_20190517_0048'),
    ]

    operations = [
        migrations.RenameField(
            model_name='pending',
            old_name='file',
            new_name='co_file',
        ),
        migrations.AddField(
            model_name='pending',
            name='do_file',
            field=models.FileField(default=None, upload_to=''),
            preserve_default=False,
        ),
        migrations.CreateModel(
            name='Revision',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('do_file', models.FileField(upload_to='')),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('pending', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SecuredVote.Pending')),
            ],
        ),
    ]