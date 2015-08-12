"""
Helpers for edx_sitespeed
"""
import json
from urlparse import urlsplit, urlunsplit


def create_headers_file(session_key, session_id, csrf_token):
    """
    Given the session information, write the cookie and CSRF headers
    to a file named "cookie.json" in the current working directory.
    """
    headers = {'Cookie': 'edxloggedin=true; {}={}; csrftoken={}'.format(
        session_key, session_id, csrf_token), 'X-CSRFToken': '{}'.format(
        csrf_token)}
    with open('cookie.json', 'w') as f:
        json.dump(headers, f)


def get_base_url(page_url):
    """
    From the URL that was passed in, compute the base URL for the server

    Args:
        page_url: A URL to any page on the edx-platform server

    Returns:
        string: Base URL for the edx-platform server

    Raises:
        ValueError if the URL passed was not valid
    """
    url = urlsplit(page_url)

    if (url.scheme == '') or (url.netloc == ''):
        msg = "'{}' is not a valid url".format(page_url)
        raise ValueError(msg)

    # Only keep the scheme and the hostname/port
    return urlunsplit((url.scheme, url.netloc, '', '', ''))
