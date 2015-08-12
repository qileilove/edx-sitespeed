"""
Tests for edx-sitespeed helpers
"""
from unittest import TestCase
from edx_sitespeed.helpers import get_base_url


class EdxSitespeedHelpersTestCase(TestCase):
    """
    TestCase class for verifying the helper methods
    """
    def test_get_base_url_already_base(self):
        page_url = "http://foo.sandbox.edx.org"
        self.assertEqual(get_base_url(page_url), page_url)

    def test_get_base_url_with_path(self):
        page_url = "http://foo.sandbox.edx.org/account/settings"
        expected_base = "http://foo.sandbox.edx.org"
        self.assertEqual(get_base_url(page_url), expected_base)

    def test_get_base_url_bad_url(self):
        with self.assertRaises(ValueError):
            get_base_url("foo")
