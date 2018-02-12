import json

from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.core.mail import EmailMessage
from django.db import models
from django.dispatch import receiver
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.db.models.signals import post_save
from django.utils import timezone


class AccountManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('Email address must be provided')

        if not password:
            raise ValueError('Password must be provided')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email=None, password=None, **extra_fields):
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields['is_staff'] = True
        extra_fields['is_superuser'] = True

        return self._create_user(email, password, **extra_fields)


class Account(AbstractBaseUser, PermissionsMixin):

    """Define a model manager for User model with no username field."""

    use_in_migrations = True


    objects = AccountManager()
    email = models.EmailField('email', unique=True, blank=False, null=False)
    full_name = models.CharField('full name', blank=True, null=True, max_length=400)
    is_staff = models.BooleanField('staff status', default=False)
    is_active = models.BooleanField('active', default=True)

    ADMIN= 1
    EMPLOYEE = 2


    ACCESS_LEVELS = (

        (ADMIN, 'Admin'),
        (EMPLOYEE, 'Employee'),

    )
    account_type = models.IntegerField(default=2, choices=ACCESS_LEVELS)
    account_profile = models.IntegerField(null=True)
    REQUIRED_FIELDS = []
    USERNAME_FIELD = 'email'

    def get_short_name(self):
        return self.email

    def get_full_name(self):
        return self.full_name



    def __unicode__(self):
        return self.email



class Profile(models.Model):
    user = models.ManyToManyField(Account)
    employee_phone_number = models.IntegerField(max_length=13, null=True)
    tax_pin = models.CharField('tax pin', max_length=40, blank=True, null=True, )
    date_hired = models.DateTimeField(default=timezone.now())
    id_number = models.IntegerField(blank=True, null=True, max_length=40)
    id_scan = models.ImageField(upload_to='media_root/uploads/', blank=True,null=True, )
    '''
    # TODO: Uploading to the specific field
    '''

def get_phone_number(self):
    return self.employee_phone_number



@receiver(post_save, sender=Account)
def update_user_profile(sender, instance, created, **kwargs):
    if created:
        subject = 'Activate Your Feedback Account'
        message = render_to_string('core/account_activation_email.html', {
            'user': instance,
            'domain': '127.0.0.1:8000',
            'uid': urlsafe_base64_encode(force_bytes(instance.pk)),
            'token': default_token_generator.make_token(instance),
        })



        # instance.email(subject, message, from_email='no-reply@mail.feedback.com')
        mail = Account.get_full_name
        email = EmailMessage(subject, message, to=[mail])
        email.send()


