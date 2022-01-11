import os
import requests


def get_payload(code):
    payload = {
        "code": code,
        "client_id": 'beta.govex.works/auth/oidc', # change for prod
        "redirect_uri": "https://subscriptions-vue.herokuapp.com/auth/oidc/callback", # change for prod
        "grant_type": "authorization_code",
    }

    return payload


def get_access_token_from_code(code):
    """Get access token for any OAuth backend from code"""

    url = "https://idp.jh.edu/idp/profile/oidc/token"
    payload = get_payload(code)
    r = requests.post(url, data=payload)
    token = {'access_token': r.json()["access_token"], 'id_token': r.json()["id_token"]}

    return token


def get_jwks_pairs(access_token):
    url = "https://idp.jh.edu/idp/profile/oidc/keyset"
    headers = {"Authorization": "Bearer " + access_token}
    response = requests.get(url, headers=headers)
    return response.json()
