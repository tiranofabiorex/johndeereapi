from requests_oauthlib import OAuth2Session
import requests
import base64
import datetime
import json
import uuid
import logging

from flask import Flask, render_template, request, redirect
import requests
import urllib.parse

app = Flask(__name__)

SERVER_URL = 'http://localhost:9010'

settings = {
    'apiUrl': 'https://sandboxapi.deere.com/platform',
    'clientId': '0oa6ipg2txMacAcEI5d7',
    'clientSecret': 'rv5mWJ160qd0oNs9J1PLlDnoXu_Uj1kFdDWrZXy_',
    'wellKnown': 'https://signin.johndeere.com/oauth2/aus78tnlaysMraFhC1t7/.well-known/oauth-authorization-server',
    'callbackUrl': f"{SERVER_URL}/callback",
    'orgConnectionCompletedUrl': SERVER_URL,
    'scopes': 'ag1 ag2 ag3 eq1 eq2 org1 org2 files offline_access',
    'state': uuid.uuid1()
}

credentials = {
    'idToken': '',
    'accessToken': '',
    'refreshToken': '',
    'apiResponse': '',
    'accessTokenDetails': '',
    'exp': ''
}


def update_token_info(res):
    json_response = res.json()
    token = json_response['access_token']
    credentials['accessToken'] = token
    credentials['refreshToken'] = json_response['refresh_token']
    credentials['exp'] = datetime.datetime.now(
    ) + datetime.timedelta(seconds=json_response['expires_in'])
    (header, payload, sig) = token.split('.')
    payload += '=' * (-len(payload) % 4)
    credentials['accessTokenDetails'] = json.dumps(json.loads(
        base64.urlsafe_b64decode(payload).decode()), indent=4)


def get_location_from_metadata(endpoint):
    response = requests.get(settings['wellKnown'])
    return response.json()[endpoint]


def get_basic_auth_header():
    return base64.b64encode(bytes(settings['clientId'] + ':' + settings['clientSecret'], 'utf-8'))


def api_get(access_token, resource_url):
    headers = {
        'authorization': 'Bearer ' + credentials['accessToken'],
        'Accept': 'application/vnd.deere.axiom.v3+json'
    }
    return requests.get(resource_url, headers=headers)


def render_error(message):
    return render_template('error.html', title='John Deere API with Python', error=message)


def get_oidc_query_string():
    query_params = {
        "client_id": settings['clientId'],
        "response_type": "code",
        "scope": urllib.parse.quote(settings['scopes']),
        "redirect_uri": settings['callbackUrl'],
        "state": settings['state'],
    }
    params = [f"{key}={value}" for key, value in query_params.items()]
    return "&".join(params)


@app.route("/connect")
def start_oidc():
    print("Chamei a função")
    redirect_url = f"{get_location_from_metadata('authorization_endpoint')}?{get_oidc_query_string()}"
    print(redirect_url)

    return redirect(redirect_url, code=302)


def needs_organization_access():
    """Check if a another redirect is needed to finish the connection.

    Check to see if the 'connections' rel is present for any organization.
    If the rel is present it means the oauth application has not completed its
    access to an organization and must redirect the user to the uri provided
    in the link.
    """
    api_response = api_get(
        credentials['accessToken'], settings['apiUrl']+'/organizations').json()
    for org in api_response['values']:
        for link in org['links']:
            if link['rel'] == 'connections':
                connectionsUri = link['uri']
                query = urllib.parse.urlencode(
                    {'redirect_uri': settings['orgConnectionCompletedUrl']})
                return f"{connectionsUri}?{query}"
    return None


@app.route("/callback")
def process_callback():
    print("Apitou callback")
    try:
        code = request.args['code']
        print(code)
        headers = {
            'authorization': 'Basic ' + get_basic_auth_header().decode('utf-8'),
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        payload = {
            'grant_type': 'authorization_code',
            'redirect_uri': settings['callbackUrl'],
            'code': code,
            'scope': settings['scopes']
        }

        res = requests.post(get_location_from_metadata(
            'token_endpoint'), data=payload, headers=headers)
        update_token_info(res)

        organization_access_url = needs_organization_access()
        if organization_access_url is not None:
            return redirect(organization_access_url, code=302)

        return client()
    except Exception as e:
        logging.exception(e)
        return render_error('Error getting token!')


@app.route("/call-api", methods=['POST'])
def call_the_api():
    try:
        url = request.form['url']
        res = api_get(credentials['accessToken'], url)
        credentials['apiResponse'] = json.dumps(res.json(), indent=4)
        return index()
    except Exception as e:
        logging.exception(e)
        return render_error('Error calling API!')


@app.route("/refresh-access-token")
def refresh_access_token():
    try:
        headers = {
            'authorization': 'Basic ' + get_basic_auth_header().decode('utf-8'),
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        payload = {
            'grant_type': 'refresh_token',
            'redirect_uri': settings['callbackUrl'],
            'refresh_token': credentials['refreshToken'],
            'scope': settings['scopes']
        }

        res = requests.post(get_location_from_metadata(
            'token_endpoint'), data=payload, headers=headers)
        update_token_info(res)
        return index()
    except Exception as e:
        logging.exception(e)
        return render_error('Error getting refresh token!')


@app.route("/client")
def client():
    return render_template('main.html', title='John Deere API with Python', settings=settings, credentials=credentials)


@app.route("/")
def index():
    return redirect("http://localhost:9010/connect")


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=9010)
