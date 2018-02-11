from django.conf.urls import url
from django.contrib.auth import views as auth_views
from django.conf.urls import url
from . import views
# from .views import account_activation_sent
from core import views as core

urlpatterns = [

    url(r'^login/$', core.LoginView.as_view(), name='login'),
    url(r'^signup/$', core.RegisterView.as_view(), name='signup'),
    url(r'^logout/$', core.LogoutView.as_view(), name='logout'),
    url(r'^daycare/create/$', core.create_daycare, name='daycare_create'),
    url(r'^daycare/view/(?P<pk>\d+)/', core.daycare_view, name='daycare_view'),
    url(r'^daycare/list/$', core.daycare_list, name='daycare_list'),

    url(r'^password_reset/$',
        auth_views.password_reset,
        {
            'template_name': 'core/registration/password_reset_form.html',
            'from_email':'no-reply@mail.feedback.com'
        },
        name='password_reset'
        ),
    url(r'^password_reset/done/$',
        auth_views.password_reset_done,
        {'template_name': 'core/registration/password_reset_done.html'},
        name='password_reset_done'),
    # url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
    #     core.activate, name='activate'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        auth_views.password_reset_confirm,
        {'template_name': 'core/registration/password_reset_confirm.html'},
        name='password_reset_confirm'
        ),
    url(r'^reset/done/$',
        auth_views.password_reset_complete,
        {'template_name': 'core/registration/password_reset_complete.html'},
        name='password_reset_complete'),
    # url(r'^account_activation_sent/$', account_activation_sent, name='account_activation_sent'),

    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.activate, name='activate'),

]




'''

    url(r'^login/$', web.LoginView.as_view(), name='login'),
    url(r'^logout/$', web.LogoutView.as_view(), name='logout'),

    url(r'^password_reset/$',
        auth_views.password_reset,
        {'template_name': 'web/registration/password_reset_form.html'},
        name='password_reset'
        ),
    url(r'^password_reset/done/$',
        auth_views.password_reset_done,
        {'template_name': 'web/registration/password_reset_done.html'},
        name='password_reset_done'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        auth_views.password_reset_confirm,
        {'template_name': 'web/registration/password_reset_confirm.html'},
        name='password_reset_confirm'
        ),
    url(r'^reset/done/$',
        auth_views.password_reset_complete,
        {'template_name': 'web/registration/password_reset_complete.html'},
        name='password_reset_complete'),

    url(r'^activate_account/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
                views.ActivateAccountView.as_view(), name='activate_account'),

    url(r'^admin/', admin.site.urls),
'''