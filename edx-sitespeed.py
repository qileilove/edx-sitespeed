import json

import requests


def login(email, password, base_url='https://courses.edx.org'):
    """Login via HTTP and parse sessionid from cookie."""
    r = requests.get('{}/login'.format(base_url))
    csrf = r.cookies['csrftoken']
    data = {'email': email, 'password': password}
    cookies = {'csrftoken': csrf}
    headers = {'referer': '{}/login'.format(base_url), 'X-CSRFToken': csrf}
    r = requests.post('{}/user_api/v1/account/login_session/'.format(base_url),
                      data=data, cookies=cookies, headers=headers)
    if r.status_code != 200:
        raise RuntimeError('failed login')
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
    email = 'user@example.com'
    password = 'secret'

    session_key, session_id = login(email, password)
    create_headers_file(session_key, session_id)
    print 'Cookie has been set in cookie.json:'
    print '{}={}\n'.format(session_key, session_id)
    print 'Please invoke sitespeed.io with `--requestHeaders cookie.json` parameter.'
