#!/usr/bin/env python

import argparse
import json

import requests


def login(email, password, base_url, auth_user=None, auth_pass=None):
    """Login via HTTP and parse sessionid from cookie."""
    if (auth_user and auth_pass):
        auth = (auth_user, auth_pass)
    else:
        auth = None

    r = requests.get('{}/login'.format(base_url), auth=auth)
    if r.status_code != 200:
        raise RuntimeError('Failed accessing the login URL. Return code: {}'.format(r.status_code))

    csrf = r.cookies['csrftoken']
    data = {'email': email, 'password': password}
    cookies = {'csrftoken': csrf}
    headers = {'referer': '{}/login'.format(base_url), 'X-CSRFToken': csrf}

    r = requests.post('{}/user_api/v1/account/login_session/'.format(base_url),
                      data=data, cookies=cookies, headers=headers, auth=auth)

    if r.status_code != 200:
        raise RuntimeError('Failed logging in. Return code: {}'.format(r.status_code))
    try:
        session_key = 'prod-edx-sessionid'
        session_id = r.cookies[session_key]  # production
    except KeyError:
        session_key = 'sessionid'
        session_id = r.cookies[session_key]  # sandbox
    return session_key, session_id


def create_headers_file(session_key, session_id):
    headers = {'Cookie': '{}={}'.format(session_key, session_id)}
    with open('cookie.json', 'w') as f:
        json.dump(headers, f)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-e', '--email', help='edX username', required=True)
    parser.add_argument('-p', '--password', help='edX password', required=True)
    parser.add_argument('-b', '--base_url', default='https://courses.edx.org',
        help='base URL (e.g. https://courses.edx.org)')
    parser.add_argument('--auth_user', help='basic auth username', default=None)
    parser.add_argument('--auth_pass', help='basic auth password', default=None)
    args = parser.parse_args()

    session_key, session_id = login(
        args.email, args.password, args.base_url, auth_user=args.auth_user, auth_pass=args.auth_pass)
    create_headers_file(session_key, session_id)

    print 'Cookie has been set in cookie.json:'
    print '{}={}\n'.format(session_key, session_id)
    print 'Please invoke sitespeed.io with `--requestHeaders cookie.json` parameter.'
