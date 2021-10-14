from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Subscription
from .serializers import SubscriptionSerializer
from rest_framework import generics
import json

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST
from requests.exceptions import HTTPError
from rest_framework import permissions, serializers, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from social_django.utils import psa

from .serializers import UserSerializer
from .utils.social.oauth import get_access_token_from_code
import base64
import json
from rest_framework.authtoken.models import Token

# @require_POST
# def logout_view(request):
#     logout(request)
#     return JsonResponse({"detail": "Logout Successful"})


# @ensure_csrf_cookie
# def login_set_cookie(request):
#     """
#     `login_view` requires that a csrf cookie be set.
#     `getCsrfToken` in `auth.js` uses this cookie to
#     make a request to `login_view`
#     """
#     return JsonResponse({"details": "CSRF cookie set"})


# @require_POST
# def login_view(request):
#     """
#     This function logs in the user and returns
#     and HttpOnly cookie, the `sessionid` cookie
#     """
#     data = json.loads(request.body)
#     username = data.get("username")
#     password = data.get("password")
#     if username is None or password is None:
#         return JsonResponse(
#             {"errors": {"__all__": "Please enter both username and password"}},
#             status=400,
#         )
#     user = authenticate(username=username, password=password)
#     if user is not None:
#         login(request, user)
#         return JsonResponse({"detail": "Success"})
#     return JsonResponse({"detail": "Invalid credentials"}, status=400)

def parse_id_token(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise Exception("Incorrect id token format")

    payload = parts[1]
    padded = payload + '=' * (4 - len(payload) % 4)
    decoded = base64.b64decode(padded)
    return json.loads(decoded)


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


class SocialSerializer(serializers.Serializer):
    """
    Serializer which accepts an OAuth2 code.
    """

    code = serializers.CharField(allow_blank=False, trim_whitespace=True,)


@api_view(http_method_names=["POST"])
@permission_classes([AllowAny])
@psa()
def exchange_token(request, backend):
    """
    Exchange an OAuth2 access token for one for this site.
    This simply defers the entire OAuth2 process to the front end.
    The front end becomes responsible for handling the entirety of the
    OAuth2 process; we just step in at the end and use the access token
    to populate some user identity.
    The URL at which this view lives must include a backend field, like:
        url(API_ROOT + r'social/(?P<backend>[^/]+)/$', exchange_token),
    Using that example, you could call this endpoint using i.e.
        POST API_ROOT + 'social/google-oauth2/'

    ## Request format
    Requests must include the following field
    - `access_token`: The OAuth2 access token provided by the provider
    """
    print(json.dumps(request))
    serializer = SocialSerializer(data=request.data)

    if serializer.is_valid(raise_exception=True):

        code = serializer.validated_data["code"]
        tokens = get_access_token_from_code(code)
        # set up non-field errors key
        # http://www.django-rest-framework.org/api-guide/exceptions/
        # #exception-handling-in-rest-framework-views
        try:
            nfe = settings.NON_FIELD_ERRORS_KEY
        except AttributeError:
            nfe = "non_field_errors"

        try:
            # this line, plus the psa decorator above, are all that's
            # necessary to
            # get and populate a user object for any properly
            # enabled/configured backend

            # which python-social-auth can handle.
            # user = request.backend.do_auth(tokens['access_token'])
            decoded = parse_id_token(tokens['id_token'])
            user = login(request, decoded['sub'], backend=settings.AUTHENTICATION_BACKENDS[0])

        except HTTPError as e:
            # An HTTPError bubbled up from the request to the social
            # auth provider.
            # This happens, at least in Google's case, every time you
            # send a malformed
            # or incorrect access key.
            return Response(
                {"errors": {"token": "Invalid token", "detail": str(e)}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user:
            if user.is_active:
                refresh = RefreshToken.for_user(user)
                return JsonResponse({'refresh': str(refresh),
                                    'access': str(refresh.access_token)})
            else:
                # user is not active; at some point they deleted their account,
                # or were banned by a superuser. They can't just log
                # in with their
                # normal credentials anymore, so they can't log in with social
                # credentials either.
                return Response(
                    {"errors": {nfe: "This user account is inactive"}},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            # Unfortunately, PSA swallows any information the backend provider
            # generated as to why specifically the authentication failed;
            # this makes it tough to debug except by examining the server logs.
            return Response(
                {"errors": {nfe: "Authentication Failed"}},
                status=status.HTTP_400_BAD_REQUEST,
            )


class Profile(APIView):
    authentication_classes = [IsAuthenticated]

    def get(self, request, format=None):
        user = request.user
        serialized_user = UserSerializer(user)
        return Response(serialized_user.data)

class SubscriptionList(generics.ListCreateAPIView):
    queryset = Subscription.objects.all()
    serializer_class = SubscriptionSerializer


class SubscriptionDetail(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]

    queryset = Subscription.objects.all()
    serializer_class = SubscriptionSerializer

