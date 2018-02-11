import json

from django.contrib.auth.tokens import default_token_generator
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager

from django.db import models
from django.dispatch import receiver
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.timezone import now, datetime
from django.utils import timezone
from django.conf import settings
from django.db.models.signals import post_save

import json
import urllib.parse
import urllib.request
from africastalking.AfricasTalkingGateway import AfricasTalkingGateway, AfricasTalkingGatewayException

# Create your models here.
#
# def get_upload_path(instance, filename):
#     return 'trap_m/{}/%Y/%m/%d/{}'.format(type(instance),filename)


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
    REQUIRED_FIELDS = []
    USERNAME_FIELD = 'email'

    objects = AccountManager()
    # primary email
    email = models.EmailField('email', unique=True, blank=False, null=False)
    full_name = models.CharField('full_name', blank=True, null=True, max_length=400)
    is_staff = models.BooleanField('staff status', default=False)
    is_active = models.BooleanField('active', default=True)
    employee_number = models.CharField(max_length=13,unique=True, null=False)
    tax_pin = models.CharField('full_name', blank=True, null=True, max_length=400)
    date_hired = models.DateField('full_name', blank=True, null=True, max_length=400)
    id_number = models.ImageField('full_name', blank=True, null=True, max_length=400)
    id_scan = models.ImageField(upload_to='ggg') #TODO: Uploading to the specific field

    ADMIN= 1
    EMPLOYEE = 2


    ACCESS_LEVELS = (

        (ADMIN, 'Admin'),
        (EMPLOYEE, 'Employee'),

    )

    account_type = models.IntegerField(default=-1, choices=ACCESS_LEVELS)
    account_profile = models.IntegerField(null=True)

    # is_verified = models.BooleanField('verified', default=False)
    # verification_uuid = models.UUIDField('Unique Verification UUID', default=uuid.uuid4)

    def get_short_name(self):
        return self.email

    def get_full_name(self):
        return self.full_name


    def get_phone_number(self):
        return self.employee_number

    def __unicode__(self):
        return self.email



@receiver(post_save, sender=Account)
# @receiver(post_save, sender=Account)
# def update_user_profile(sender, instance, created, **kwargs):
def update_user_profile(sender, instance, created, **kwargs):
    if created:
        subject = 'Activate Your Feedback Account'
        message = render_to_string('core/account_activation_email.html', {
            'user': instance,
            'domain': '127.0.0.1:8000',
            'uid': urlsafe_base64_encode(force_bytes(instance.pk)),
            'token': default_token_generator.make_token(instance),
        })




        instance.email_user(subject, message, from_email='no-reply@mail.feedback.com')


        # url_to_shorten = message.











def get_user_name():
    return settings.AFRICASTALKING_USERNAME


def get_api_key():
    return settings.AFRICASTALKING_APIKEY


# def get_sender():
#     return settings.AFRICASTALKING_SENDER


# Create your models here.




class GooglException(Exception):
    def __init__(self, message, code, errors):
        super().__init__(message)
        self.code = code
        self.errors = errors


def shortenURL(url_to_shorten):
    """
    Given a URL, return a goo.gl shortened URL
    Arguments
    ---------
        url_to_shorten : string
            The URL you want to shorten
    Returns
    -------
        Shortened goo.gl URL string
    Raises
    ------
        GooglException
            If something goes wrong with the HTTP request
    """

    # The goo.gl API URL
    api_url = 'https://www.googleapis.com/urlshortener/v1/url'
    # Construct our JSON dictionary
    data = json.JSONEncoder().encode({'longUrl': url_to_shorten})
    # Encode to UTF-8 for sending
    data = data.encode('utf-8')
    # HTTP header
    headers = {"Content-Type": "application/json"}
    # Construct the request
    request = urllib.request.Request(api_url, data=data, headers=headers)

    # Make the request and get the response to read from
    try:
        response = urllib.request.urlopen(request)
        success = True
    # If a HTTPError occurs, we will be reading from the error instead
    except urllib.error.HTTPError as err:
        response = err
        success = False
    # Read the response object, decode from utf-8 and convert from JSON
    finally:
        data = json.loads(response.read().decode('utf8'))

    # Return our shortened URL
    if success:
        return data['id']
    # Or raise an Exception
    else:
        raise GooglException(data['error']['message'], data['error']['code'], data['error']['errors'])


class SendSMS(object):
    pass


class Message(models.Model):
    text = models.TextField()
    send_time = models.DateTimeField(auto_now=True)



    def send(self):
        # Sending Messages using sender id/short code
        # message_x = self.message()
        # api_credentials,created = api_gateway_settings.objects.get_or_create()
        username = get_user_name()
        apikey = get_api_key()
        contacts = Account.employee_number

        if not contacts.exists():
            # contacts = Contact.objects.filter(sendsms__message=self, sendsms__status=SendSMS.FAILED)
            print('Contact Does not exist')

        if not contacts:
            return

        to = ','.join(contacts.values_list('number',flat=True))
        # message = message_x
        # Specify your AfricasTalking shortCode or sender id
        # sender = api_credentials.sender
        gateway = AfricasTalkingGateway(username, apikey)

        try:
            results = gateway.sendMessage(to, self.text)
            # results = gateway.sendMessage(to, self.text, sender)
            for recipient in results:
                number = recipient['number']
                status = recipient['status']
                message_id = recipient['messageId']
                cost = recipient['cost']

                employee_number = Account.objects.get(number=number)
                send_sms = SendSMS.objects.get(message=self,recipient=employee_number)

                if status == 'Success': # and cost != 0:
                    send_sms.status = 1
                    send_sms.reference = message_id
                    send_sms.cost = cost
                    # send_sms.sent_time = now
                else:
                    send_sms.status = 2

                send_sms.save()

                # Note that only the Status "Success" means the message was sent
                print('number=%s;status=%s;messageId=%s;cost=%s' % (
                    recipient['number'],
                    recipient['status'],
                    recipient['messageId'],
                    recipient['cost']))

        except AfricasTalkingGatewayException as e:
            print ('Encountered an error while sending: %s' % str(e))

    def __str__(self):
        return self.text

    # class Meta:
    #     ordering = ['-id']

# class SendSMS(models.Model):
#     WAITTING = 0
#     FAILED = 2
#
#     SEND_STATUS = (
#         (0,'WAITTING'),
#         (1,'SENT'),
#         (2,'FAILED'),
#     )
#
#     recipient = models.ForeignKey(Account.get_phone_number, on_delete=models.CASCADE)
#     status = models.IntegerField(choices=SEND_STATUS,default=0)
#     message = models.ForeignKey(Message, on_delete=models.CASCADE)
#
#     # sent_time = models.DateTimeField(default=now)
#     reference = models.CharField(max_length=50, blank=True, default='')
#     cost = models.CharField(max_length=50, blank=True, default='')
#


