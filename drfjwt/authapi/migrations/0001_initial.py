# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import datetime
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0006_require_contenttypes_0002'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('created_date', models.DateTimeField(default=datetime.datetime(2017, 9, 29, 11, 39, 36, 13576))),
                ('user', models.OneToOneField(primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
                ('phone_number', models.CharField(max_length=15, null=True, blank=True)),
                ('date_of_birth', models.DateTimeField(null=True, blank=True)),
                ('gender', models.CharField(blank=True, max_length=2, null=True, choices=[(b'M', b'Male'), (b'F', b'Female'), (b'X', b'others')])),
                ('agree', models.BooleanField(default=False)),
                ('terms_conditions', models.BooleanField(default=False)),
            ],
            options={
                'db_table': 'puc_userprofile',
            },
        ),
    ]
