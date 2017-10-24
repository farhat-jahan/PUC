from django.db import models
from datetime import datetime
from django.contrib.auth.models import User
from django.core.validators import RegexValidator
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
    phone_regex = RegexValidator(regex=r'^\d{10,15}$',
                                 message="Phone number must be entered in the format: '9999999999'. Up to 15 digits allowed.")
    phone_number = models.CharField(validators=[phone_regex], max_length=15, blank=True,unique=True)
    date_of_birth = models.DateTimeField(blank=True, null=True)
    gender = models.CharField(max_length=2, choices=constants.GENDER_CHOICE, blank=True, null=True)
    agree = models.BooleanField(default=False)
    terms_conditions = models.BooleanField(default=False)
    reset_password = models.BooleanField(default=False)
    reset_password_date = models.DateTimeField(null=True)

    class Meta:
        db_table = "puc_userprofile"


