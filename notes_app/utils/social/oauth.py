import os
import requests


def get_payload(code):

    payload = {
            "code": code,
            "client_id": '544259183679-ijbi8vh8sv4aneo5sqqe5pirhpn57ko7.apps.googleusercontent.com',
            "client_secret": 'SJ8lCpcbIeD0AJV6eRmiXO8w',
            "redirect_uri": "http://127.0.0.1:8080/auth/google-oauth2/callback",
            "grant_type": "authorization_code",
        }

    return payload


def get_access_token_from_code(code):
    """Get access token for any OAuth backend from code"""

    url = "https://oauth2.googleapis.com/token"
    payload = get_payload(code)

    # google returns this:
    # {
    #   'access_token': 'ya29.frejf8erf.erferfeg.erfeogOS9tzAPQlNlUXitkMbmSt',
    #   'expires_in': 3596,
    #   'scope': 'openid https://www.googleapis.com/auth/userinfo.email',
    #   'token_type': 'Bearer',
    #   'id_token': 'oierfoie940j.ferferfoprek/refpekf9efoeik.long token'
    # }
    r = requests.post(url, data=payload)
    token = r.json()["access_token"]

    return token
