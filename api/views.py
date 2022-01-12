from django.conf import settings
from django.contrib.auth import authenticate
from django.http import JsonResponse
from requests.exceptions import HTTPError
from rest_framework import permissions, serializers, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer
from .utils.social.oauth import get_access_token_from_code
from .utils.social.oauth import get_jwks_pairs
import base64
import json
import jwt
import requests


def redirect_auth(request):  # not needed for prod, was just used for testing
    payload = {
        "code": request.GET.get('code')
    }
    r = requests.post('https://beta.govex.works/auth/oidc', data=payload)
    # return HttpResponseRedirect('https://subscriptions-vue.herokuapp.com/auth/oidc/callback?code='+code)


def parse_id_token(token: str) -> list:
    parts = token.split(".")
    if len(parts) != 3:
        raise Exception("Incorrect id token format")

    headers = parts[0]
    payload = parts[1]
    padded_headers = headers + '=' * (4 - len(headers) % 4)
    padded_payload = payload + '=' * (4 - len(payload) % 4)
    decoded_headers = base64.b64decode(padded_headers)
    decoded_payload = base64.b64decode(padded_payload)

    return [json.loads(decoded_headers), json.loads(decoded_payload)]


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

    code = serializers.CharField(allow_blank=False, trim_whitespace=True, )


@api_view(http_method_names=["POST"])
@permission_classes([AllowAny])
def exchange_token(request):
    """
    Exchange an OAuth2 access token for one for this site.
    This simply defers the entire OAuth2 process to the front end.
    The front end becomes responsible for handling the entirety of the
    OAuth2 process; we just step in at the end and use the access token
    to populate some user identity.

    ## Request format
    Requests must include the following field
    - `access_token`: The OAuth2 access token provided by the provider
    """
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
            # Validate the keys' ids match from the decoded id token
            # and the keyset derived from the jwks then validate the signature
            # is legitimately from JHU
            decoded_id_token = parse_id_token(tokens['id_token'])
            keyset = get_jwks_pairs(tokens['access_token'])

            if decoded_id_token[0]['kid'] == keyset['keys'][0]['kid']:
                webkey = keyset['keys'][0]
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(webkey)
                user = jwt.decode(tokens['id_token'], public_key, algorithms=['RS256'],
                                  audience="beta.govex.works/auth/oidc")  # audience is required, change for prod
                user = authenticate(user['sub'])

        except HTTPError as e:
            return Response(
                {"errors": {"token": "Invalid token", "detail": str(e)}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user:
            if user.is_active:
                token = RefreshToken.for_user(user)
                return JsonResponse({'refresh': str(token),
                                     'access': str(token.access_token)})
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


# possibly not needed, may use a getUser(pkey) method to get the complete user object instead
@permission_classes([IsAuthenticated])
class Profile(APIView):

    def get(self, request, format=None):
        user = request.user
        serialized_user = UserSerializer(user)
        return Response(serialized_user.data)
