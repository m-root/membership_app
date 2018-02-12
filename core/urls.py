from django.contrib.auth import views as auth_views
from django.conf.urls import url
from . import views
from core import views as core

app_name = 'core'
urlpatterns = [

    url(r'^$', core.index, name='index'),
    url(r'^login/$', core.LoginView.as_view(), name='login'),
    url(r'^signup/$', core.signup, name='signup'),
    url(r'^profile/$', core.ProfileDetailView.as_view(), name='profile'),
    url(r'^member/edit/$', core.edit_user, name='member_edit'),
    url(r'^password_reset/$',
        auth_views.password_reset,
        {
            'template_name': 'core/registration/password_reset_form.html',
            'from_email':'no-reply@mail.feedback.com'
        },
        name='password_reset'
        ),
    url(r'^logout/$', web.LogoutView.as_view(), name='logout'),
    url(r'^password_reset/done/$',
        auth_views.password_reset_done,
        {'template_name': 'core/registration/password_reset_done.html'},
        name='password_reset_done'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        auth_views.password_reset_confirm,
        {'template_name': 'core/registration/password_reset_confirm.html'},
        name='password_reset_confirm'
        ),
    url(r'^reset/done/$',
        auth_views.password_reset_complete,
        {'template_name': 'core/registration/password_reset_complete.html'},
        name='password_reset_complete'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/account/$',
        views.activate_user_account, name='activate_user_account'),

]

