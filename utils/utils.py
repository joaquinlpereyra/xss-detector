from functools import wraps
from logs.logger import logger
import requests

class WebIO:
    """A class to handle all requests to the web."""
    def __init__(self, cookies):
        """Hold the cookies given as parameter."""
        self.cookies = cookies

    def safe_website_io(self, func, url, *args, **kwargs):
        """All requests finally end up here. We don't want our Workers
        to crash if there was a problem accesing the URL, so try/except that
        and return None. If everything went fine, return whatever
        func would have returned."""
        try:
            return func(url, cookies=self.cookies, timeout=2, *args, **kwargs)
        except requests.exceptions.RequestException:
            logger.warning("Could not connect to the URL {0}. ".format(url))
            return None

    def get_website_as_string(self, url):
        """Get the website as a string, or None if it was not possible."""
        website = self.safe_website_io(requests.get, url)
        if website:
            return website.text

    def get_page_response(self, base_url, method, is_upload, payload):
        """Gets the base_url response when a request with method method
        and payload payload is given."""
        if method == 'get':
            response = self.safe_website_io(requests.get, base_url, params=payload)
        elif method == 'post' and is_upload:
            response = self.safe_website_io(requests.post, base_url, files=payload)
        elif method == 'post' and not is_upload:
            response = self.safe_website_io(requests.post, base_url, data=payload)
        else:
            response = None
        return response

    def was_request_accepted(self, url, method, is_upload, payload):
        """Return True if the the url url gave a status code between 200 and 300
        when requesting via the method method and payload payload. Else,
        return False.
        """
        response = self.get_page_response(url, method, is_upload, payload)
        if response and 200 <= response.status_code < 300:
            request_acceped = True
        else:
            request_acceped = False
        return request_acceped
