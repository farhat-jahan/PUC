# -*- coding: utf-8 -*-
# Generated by Django 1.9.2 on 2017-10-04 07:31
from __future__ import unicode_literals

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authapi', '0002_auto_20171004_0715'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='created_date',
            field=models.DateTimeField(default=datetime.datetime(2017, 10, 4, 7, 31, 28, 488784)),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='reset_password_date',
            field=models.DateTimeField(null=True),
        ),
    ]
