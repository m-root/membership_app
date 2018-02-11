from django import forms
from .models import Account
# from .models import Member,Account
from django.utils.timezone import datetime
from django.contrib.auth.forms import UserCreationForm
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import Account


class AccountForm(UserCreationForm):

    def clean_number(self):

        number = self.cleaned_data.strip()['number']

        if (number[0] == '0'): # e.g 0717667590
            number = '+254' + number[1:11]
        elif (number[0] == '7'): # e.g 717667590
            number = '+254' + number[0:10]
        elif (number[0] == '2'): # e.g 254717667590
            number = '+' + number[0:13]
        elif (number[0] == '+'): # e.g +254717667590
            number = number[0:14]
        else:
            raise forms.ValidationError("Invalid Number")
        number = number[1:14]
        return number


    class Meta:
        model = Account
        # fields = ('email', 'full_name', 'email', 'password1', 'password2','account_type')
        exclude = []

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request")
        super(UserForm, self).__init__(*args, **kwargs)



    # def save(self, commit=True):
    #     activity = super(MemberForm, self).save(commit=False)
    #     activity.created_by = self.request.user
    #     # 'start_at_date': ['12/12/2017'], 'start_at_time': ['06:30'],
    #     print(self.cleaned_data)
    #
    #     # self.cleaned_data.get
    #
    #     if commit:
    #         activity.save()
    #     return activity





class SignupForm(UserCreationForm):
    email = forms.EmailField(max_length=200, help_text='Required')
    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')