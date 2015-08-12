#!/usr/bin/env python

import argparse
import requests

from helpers import get_base_url, create_headers_file


def login(email, password, url, auth_user=None, auth_pass=None):
    """
    Log in to the edX application via HTTP and parse sessionid from cookie.

    Args:
        email: Email address of edX user
        password: Password for the edX user
        url: Url of the edX application
        auth_user (Optional): Basic auth username
        auth_pass (Optional): Basic auth password

    Returns:
        A dictionary with the data needed to create a headers file for
            sitespeed.io, that will access the edX application as a
            logged-in user.
            {
                'session_key': name of the session key cookie,
                'session_id': the sessionid on the edx platform
                'csrf_token': the csrf token
            }

    Raises:
        RuntimeError: If the login page is not accessible or the login fails.

    """
    if (auth_user and auth_pass):
        auth = (auth_user, auth_pass)
    else:
        auth = None

    base_url = get_base_url(url)
    r = requests.get('{}/login'.format(base_url), auth=auth)
    if r.status_code != 200:
        msg = 'Failed accessing the login URL. Return code: {}'.format(
            r.status_code)
        raise RuntimeError(msg)

    csrf = r.cookies['csrftoken']
    data = {'email': email, 'password': password}
    cookies = {'csrftoken': csrf}
    headers = {'referer': '{}/login'.format(base_url), 'X-CSRFToken': csrf}

    r = requests.post('{}/user_api/v1/account/login_session/'.format(base_url),
                      data=data, cookies=cookies, headers=headers, auth=auth)

    if r.status_code != 200:
        msg = 'Failed logging in. Return code: {}'.format(r.status_code)
        raise RuntimeError(msg)
    try:
        session_key = 'prod-edx-sessionid'
        session_id = r.cookies[session_key]  # production
    except KeyError:
        session_key = 'sessionid'
        session_id = r.cookies[session_key]  # sandbox
    return {'session_key': session_key, 'session_id': session_id,
            'csrf_token': csrf}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-e', '--email', help='edX username', required=True)
    parser.add_argument('-p', '--password', help='edX password', required=True)
    parser.add_argument('-u', '--url', default='https://courses.edx.org',
                        help='URL (e.g. https://courses.edx.org)',
                        required=True)
    parser.add_argument('--auth_user', help='basic auth username',
                        default=None)
    parser.add_argument('--auth_pass', help='basic auth password',
                        default=None)
    args = parser.parse_args()

    session_info = login(
        args.email, args.password, args.url, auth_user=args.auth_user,
        auth_pass=args.auth_pass)
    create_headers_file(
        session_info['session_key'], session_info['session_id'],
        session_info['csrf_token'])

    print 'Cookie has been set in cookie.json.'
    print 'Please invoke sitespeed.io with `--requestHeaders cookie.json`.'
