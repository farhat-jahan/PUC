from django.db import models
from datetime import datetime
from django.contrib.auth.models import User
from . import constants

# user fields:password,last_login,is_superuser,username,first_name,last_name,email,is_staff,is_active,date_joined
class BaseModel(models.Model):
    """ Base model containing created date """
    created_date =  models.DateTimeField(default=datetime.now())

    class Meta:
        abstract = True

class UserProfile(BaseModel):
    """ User profile model to extend user """

    user = models.OneToOneField(User, primary_key=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    date_of_birth = models.DateTimeField(blank=True, null=True)
    gender = models.CharField(max_length=2, choices=constants.GENDER_CHOICE, blank=True, null=True)
    agree = models.BooleanField(default=False)
    terms_conditions = models.BooleanField(default=False)
    reset_password = models.BooleanField(default=False)
    reset_password_date = models.DateTimeField(null=True)

    class Meta:
        db_table = "puc_userprofile"



