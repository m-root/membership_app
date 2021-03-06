from django.http import HttpResponseRedirect
from django.urls import reverse
from django.conf import settings
from re import compile
from django.utils.deprecation import MiddlewareMixin

EXEMPT_URLS = [compile(settings.LOGIN_URL.lstrip('/'))]
if hasattr(settings, 'LOGIN_EXEMPT_URLS'):
    EXEMPT_URLS += [compile(expr) for expr in settings.LOGIN_EXEMPT_URLS]


class AuthRequiredMiddleware(MiddlewareMixin):
    """
    Middleware that requires a user to be authenticated to view any page other
    than LOGIN_URL. Exemptions to this requirement can optionally be specified
    in settings via a list of regular expressions in LOGIN_EXEMPT_URLS (which
    you can copy from your urls.py).
    Requires authentication middleware and template context processors to be
    loaded. You'll get an error if they aren't.
    """

    def process_request(self, request):
        assert_error_message = '''
        The Login Required middleware requires authentication middleware to be installed. 
        Edit your MIDDLEWARE_CLASSES setting to insert 'django.contrib.auth.middleware.AuthenticationMiddleware'. 
        If that doesn't work, 
        ensure your TEMPLATE_CONTEXT_PROCESSORS setting includes 'django.core.context_processors.auth'
        '''

        assert hasattr(request, 'user'), assert_error_message
        path = request.path_info.lstrip('/')
        #
        # if request.user.is_authenticated():
        #     if not any(m.match(path) for m in EXEMPT_URLS):
        #         # TODO : add ?next query param only if a path exists
        #         return HttpResponseRedirect(settings.INDEX_URL.format(path))

        if not request.user.is_authenticated:
        # if not request.user.is_authenticated():
            if not any(m.match(path) for m in EXEMPT_URLS):
                # TODO : add ?next query param only if a path exists
                return HttpResponseRedirect(settings.LOGIN_URL + '?next={}'.format(path))

        # elif request.user.is_authenticated():
        #     if not any(m.match(path) for m in EXEMPT_URLS):
        #         # TODO : add ?next query param only if a path exists
        #         return HttpResponseRedirect(settings.INDEX_URL.format(path))

        else:
            # TODO : use regex to match all paths inaccessible after login
            # forgot_password/,login/,reset/
            if path == 'login/':
                return HttpResponseRedirect(settings.INDEX_URL)
