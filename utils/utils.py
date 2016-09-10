from functools import wraps
from logs.logger import logger
import requests

def _safe_io_with_website(func):
    @wraps(func)
    def safe_wrapper(web_io, func, url, *args, **kwargs):
        try:
            return func(url, *args, **kwargs)
        except requests.exceptions.RequestException:
            logger.warning("Could not connect to the URL {0}. ".format(url))
            return None
    return safe_wrapper

class SafeIO:
    def __init__(self, cookies):
        self.cookies = cookies

    @_safe_io_with_website
    def website_io(self, func, url, **kwargs):
        return func(url, cookies=self.cookies, timeout=2, **kwargs)

    def get_website_as_string(self, url):
        website = self.website_io(requests.get, url)
        if website:
            return website.text

    def get_page_response(self, base_url, method, is_upload, payload):
        if method == 'get':
            response = self.website_io(requests.get, base_url, params=payload)
        elif method == 'post' and is_upload:
            response = self.website_io(requests.post, base_url, files=payload)
        elif method == 'post' and not is_upload:
            response = self.website_io(requests.post, base_url, data=payload)
        else:
            response = None
        return response

    def was_request_accepted(self, url, method, is_upload, payload):
        response = self.get_page_response(url, method, is_upload, payload)
        if response and 200 <= response.status_code < 300:
            request_acceped = True
        else:
            request_acceped = False
        return request_acceped

