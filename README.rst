-------------
edx-sitespeed
-------------

create an authenticated edX session for use with sitespeed.io.

About Sitespeed
---------------

**Sitespeed.io** is an open source tool that helps you analyze your website speed and performance based on best practice rules and timing metrics.

see: http://www.sitespeed.io

----

To run sitespeed.io against edX, you must have an authenticated (logged in) user with an active session.
Sitespeed.io allows you to pass in HTTP headers using .json in a file.
We use this to pass a valid cookie that can be used in the browser during sitespeed.io's crawl.

The ``edx_sitespeed.py`` script takes care of getting a valid cookie and writing it to file in .json format.

----

Usage:
------

``edx_sitespeed.py [-h] -e EMAIL -p PASSWORD -u URL [--auth_user AUTH_USER] [--auth_pass AUTH_PASS]``

Example:
--------

``$ python edx_sitespeed.py -e honor@example.com -p edx -u http://my.sandbox.edx.org``

This will create a ``cookie.json`` file.
At this point, you are ready to invoke sitespeed.io, using the ``--requestHeaders cookie.json`` parameter.
