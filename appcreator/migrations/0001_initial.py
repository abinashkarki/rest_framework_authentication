# Generated by Django 3.0.8 on 2021-11-12 06:29

import appcreator.models
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='application',
            fields=[
                ('appid', models.AutoField(default=0, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('logo', models.ImageField(upload_to=appcreator.models.upload_to, verbose_name='images')),
            ],
        ),
    ]
