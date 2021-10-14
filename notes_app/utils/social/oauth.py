import os
import requests


def get_payload(code):

    payload = {
            "code": code,
            "client_id": 'beta.govex.works/auth/oidc',
            # "client_secret": 'SJ8lCpcbIeD0AJV6eRmiXO8w',
            "redirect_uri": "https://beta.govex.works/auth/oidc/callback",
            "grant_type": "authorization_code",
        }

    return payload


def get_access_token_from_code(code):
    """Get access token for any OAuth backend from code"""

    url = "https://idp.jh.edu/idp/profile/oidc/token"
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
    token = {'access_token': r.json()["access_token"], 'id_token': r.json()["id_token"]}
    print(token)

    return token
