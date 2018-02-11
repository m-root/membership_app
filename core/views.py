import logging
from django.contrib.auth.decorators import login_required
from core.models import Account
import json
import requests
from africastalking.AfricasTalkingGateway import AfricasTalkingGateway, AfricasTalkingGatewayException
from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login, logout as auth_logout
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import render, redirect, get_object_or_404
from django.utils.decorators import method_decorator
from django.utils.http import is_safe_url
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, RedirectView
from django.urls import reverse
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth.tokens import default_token_generator
from .forms import AccountForm
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string



# Create your views here.
log = logging.getLogger(__name__)




###########################################################
# SENDING ACCOUNT USER ACTIVATION EMAIL
###########################################################
def send_account_activation_email(request, user):
    text_content = 'Account Activation Email'
    subject = 'Email Activation'
    template_name = "emails/account/activation.html"
    from_email = settings.DEFAULT_FROM_EMAIL
    recipients = [user.email]
    kwargs = {
        "uidb64": urlsafe_base64_encode(force_bytes(user.pk)).decode(),
        "token": default_token_generator.make_token(user)
    }
    activation_url = reverse("activate_user_account", kwargs=kwargs)

    activate_url = "{0}://{1}{2}".format(request.scheme, request.get_host(), activation_url)

    context = {
        'user': user,
        'activate_url': activate_url
    }




    html_content = render_to_string(template_name, context)
    email = EmailMultiAlternatives(subject, text_content, from_email, recipients)
    email.attach_alternative(html_content, "text/html")
    email.send()

    return HttpResponse(activate_url)


###########################################################
# ACCOUNT USER ACTIVATION
###########################################################
def activate_user_account(request, uidb64=None, token=None):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = Account.objects.get(pk=uid)
    except Account.DoesNotExist:
        user = None
    if user and default_token_generator.check_token(user, token):
        user.is_email_verified = True
        user.is_active = True
        user.save()
        login(request, user)
        return redirect('userprofile')
    else:
        return HttpResponse("Activation link has expired")



###########################################################
# ACCOUNT LOGIN VIEW
###########################################################
class LoginView(FormView):
    """
    Provides the ability to login as a user with a username and password
    """
    template_name = 'core/login.html'
    success_url = '/'
    form_class = AuthenticationForm
    redirect_field_name = REDIRECT_FIELD_NAME

    @method_decorator(sensitive_post_parameters('password'))
    @method_decorator(csrf_protect)
    @method_decorator(ensure_csrf_cookie)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        # Sets a test cookie to make sure the user has cookies enabled
        # request.session.set_test_cookie()
        # log.info("Test Cookie Set")
        return super(LoginView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        auth_login(self.request, form.get_user())
        # If the test cookie worked, go ahead and
        # delete it since its no longer needed
        # if self.request.session.test_cookie_worked():
        #    log.info('test cookie worked')
        #    self.request.session.delete_test_cookie()

        return super(LoginView, self).form_valid(form)

    def get_success_url(self):
        redirect_to = self.request.GET.get(self.redirect_field_name)
        if not is_safe_url(url=redirect_to, host=self.request.get_host()):
            redirect_to = self.success_url
        return redirect_to

###########################################################
# REGISTRATION VIEW
###########################################################
class RegisterView(FormView):
    """
    Provides the ability to register user with a username and password
    """
    template_name = 'core/register.html'
    success_url = '/account_activation_sent/'
    form_class = AccountForm
    redirect_field_name = REDIRECT_FIELD_NAME

    @method_decorator(sensitive_post_parameters('password', 'password2'))
    @method_decorator(csrf_protect)
    @method_decorator(ensure_csrf_cookie)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        # Sets a test cookie to make sure the user has cookies enabled
        # request.session.set_test_cookie()
        # log.info("Test Cookie Set")
        return super(RegisterView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.save()
        # auth_login(self.request, user)

        return super(RegisterView, self).form_valid(form)

    def get_success_url(self):
        redirect_to = self.request.GET.get(self.redirect_field_name)
        if not is_safe_url(url=redirect_to, host=self.request.get_host()):
            redirect_to = self.success_url
        return redirect_to

###########################################################
# LOGOUT VIEW
###########################################################

class LogoutView(RedirectView):
    """
    Provides users the ability to logout
    """
    template_name = 'core/logout.html'
    url = '/'

    def get(self, request, *args, **kwargs):
        auth_logout(request)
        return super(LogoutView, self).get(request, *args, **kwargs)



###########################################################
# CALLING AFRICA'S TALKING USERNAME
###########################################################

def get_user_name():
    return settings.AFRICASTALKING_USERNAME

###########################################################
# CALLING AFRICA'S TALKING APIKEY
###########################################################

def get_api_key():
    return settings.AFRICASTALKING_APIKEY

###########################################################
# CALLING GOOGLE API KEY
###########################################################

def get_google_api_key():
    return settings.GOOGLE_URL_APIKEY







f = send_account_activation_email()
# url = send_account_activation_email.
# x = url
message_for_all='Hello\n\nThank you for signing up. Please verify your Account using the link below \n \n' + send_account_activation_email()

###########################################################
# URL SHORTENING BY
###########################################################

class GUrlShorten():
    # def __init__(self, key):
    #     self.API_KEY = key

    def google_url_shorten(url):
        req_url = 'https://www.googleapis.com/urlshortener/v1/url?key=' + get_google_api_key()
        payload = {'longUrl': url}
        headers = {'content-type': 'application/json'}
        r = requests.post(req_url, json=payload, headers=headers)
        resp = json.loads(r.text)
        return resp['id']

# SENDING A SMS

def send_sms():

    username = get_user_name()
    apikey = get_api_key()
    to = "+254712160428"

    message = message_for_all
    gateway = AfricasTalkingGateway(username, apikey)

    try:
        results = gateway.sendMessage(to, message)
        for recipient in results:
            print(
            'number=%s;status=%s;messageId=%s;cost=%s' % (recipient['number'],
                                                          recipient['status'],
                                                          recipient['messageId'],
                                                          recipient['cost']))
    except AfricasTalkingGatewayException as e:
        print ('Encountered an error while sending: %s' % str(e))







###########################################################
# LISTING ALL MEMBERS
###########################################################
@login_required
# if Account.profile.role ==
def member_list(request):
    members = Account.objects.all()
    context = {}
    context['object_list'] = members
    return render(request, '', context)

###########################################################
# CREATING A MEMBER
###########################################################

def create_member(request):
    context = {}
    if request.method == "POST":
        form = AccountForm(data=request.POST)
        if form.is_valid():
            form.save() #TODO: Redirect and template
            return redirect('core/daycare/list/')
    else:
        form = AccountForm()
    return render(request,'core/daycare/daycare_create.html', context)



###########################################################
# UPDATING A MEMBER
###########################################################

@login_required
def member_update(request, pk):
    book= get_object_or_404(Account, pk=pk)
    form = AccountForm(request.POST or None, instance=book)
    context = {}
    if form.is_valid():
        form.save()
        return redirect('books_fbv:book_list')
    return render(request, '', context)






###########################################################
# DELETING A MEMBER
###########################################################
def member_delete(request, pk):
    book= get_object_or_404(Account, pk=pk)
    context = {}
    if request.method=='POST':
        book.delete()
        return redirect('members_list')#TODO: add the right link
    return render(request, '', context)








