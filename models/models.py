import requests
import json
import glob
from urllib.parse import urlparse
from bs4 import BeautifulSoup

"""A module that holds all the main classes of the application.  """

class ScrappedWebsite:
    """A ScrappedWebsite is a website parsed with BeautifulSoup and
    with methods prepared to extract information about its DOM."""
    def __init__(self, url, html_string):
        """Inits the ScrappedWebsite with a url (stripping away the ending /
        if it has it) and parsing it with BS."""
        self.url = url if not url.endswith('/') else url[:-1]
        self._parsed_url = urlparse(self.url)
        self._scheme = self._parsed_url.scheme
        self._domain_name = self._parsed_url.netloc
        self._soup = BeautifulSoup(html_string, 'html.parser')

    def _is_on_same_domain(self, link):
        """Return True if link is on same domain as the original website."""
        netloc = urlparse(link).netloc
        return netloc == self._domain_name

    def _if_no_netlock_rebuild_link(self, relative_link):
        """Return a rebuilit, absolute URL if the link is a relative link.
        Else, just return the original link.
        """
        if not urlparse(relative_link).netloc:
            return "{0}://{1}{2}".format(self._parsed_url.scheme,
                                          self._parsed_url.netloc,
                                          relative_link)
        return relative_link

    def get_unique_relevant_links(self):
        """Return all the links found on the webpage which point
        to the same network location. There are no duplicates on the returned
        list.
        """
        raw_links = []
        for link in self._soup.find_all('a'):
            raw_links.append(link.get('href'))
        links = list(map(self._if_no_netlock_rebuild_link, raw_links))
        links = list(filter(self._is_on_same_domain, links))
        unique_links = set(links)
        return unique_links

    def _rebuild_action_link(self, action):
        return self.url if action is None else self._if_no_netlock_rebuild_link(action)

    def get_exposed_inputs(self):
        """Return a list with tuples of (method, action, is_upload, name), where
        method is either 'GET' or 'POST', action is the action
        of the exposed form, is_upload specifies if the form expects us to
        upload a file and query_name is the name of the input in the form
        """
        def discriminate_query_type(query_type):
            return True if query_type == 'file' else False

        def lower_strings(*strings):
            return [s.lower() for s in strings]

        methods_actions_urls_and_names = []
        for form in self._soup.find_all('form'):
            action = self._rebuild_action_link(form.get('action'))
            for input_ in form.find_all('input'):
                query_type = input_.get('type')
                is_upload = discriminate_query_type(query_type)
                query_name = input_.get('name') or ''
                method = form.get('method')
                method, action, query_name = lower_strings(method, action, query_name)
                methods_actions_urls_and_names.append((method, action,
                                                       is_upload, query_name))
        return methods_actions_urls_and_names

class XSS:
    """A simple class to represent the XSS vulnerability.
    Holds the URL where it was found, the payload that got through
    and the method ('GET' or 'POST')"""
    def __init__(self, url, payload, method):
        self.url = url
        self.payload = json.dumps(payload)
        self.method = method

    def __str__(self):
        return ("XSS found on URL {0} with parameters {1} "
                "via method {2}".format(self.url, self.payload, self.method))

class XSSDetector:
    """A class with methods and attributes to aid in the search of
    xss in a scrapped_website (instance of ScrappedWebsite)."""
    def __init__(self, scrapped_website, web_io):
        """Attachs the scrapped website and web_io class to the instance.
        It also creates the attack_information upon initialization.

        Web_io should be an instance of SafeIO found on utils.
        """
        self._scrapped_website = scrapped_website
        self._get_tests = self._file_lines_as_list('xss_tests/get_method')
        self._post_tests = self._file_lines_as_list('xss_tests/post_method')
        self._common_tests = self._file_lines_as_list('xss_tests/common')
        self._file_upload_tests = [self._file_as_str(f) for f in glob.glob('xss_tests/upload_tests/*')]
        self.attack_information = self._create_attack_information()
        self.web_io = web_io

    def _file_lines_as_list(self, file_):
        try:
            with open(file_, 'r') as f:
                file_lines_as_list = f.read().splitlines()
        except FileNotFoundError:
            return []
        return file_lines_as_list

    def _file_as_str(self, file_):
        try:
            with open(file_, 'r') as f:
                file_as_string = f.read()
        except FileNotFoundError:
            file_as_string = ''
        return file_as_string
    def _create_attack_information(self):
        """Return a list of tuples that look like
        (url, method, is_upload, {query_parameter: test}), where url is
        the url to where the request will be sent, method is either
        'GET' or 'POST', query_parameter is the name of the input of a form
        on the scrapped website or '' and test is one the tests.
        """
        def build_payload_and_append(method, url, is_upload, query_name, source_lst):
            for test in source_lst:
                payload = {query_name: test}
                method_url_is_upload_and_payloads.append((method, url, is_upload, payload))

        method_url_is_upload_and_payloads = []
        exposed_inputs = self._scrapped_website.get_exposed_inputs()
        for method, url, is_upload, query_name in exposed_inputs:
            build_payload_and_append(method, url, is_upload,
                                     query_name, self._common_tests)
            if method == 'get':
                build_payload_and_append(method, url, is_upload,
                                         query_name, self._get_tests)
            elif method == 'post' and not is_upload:
                build_payload_and_append(method, url, is_upload,
                                         query_name, self._post_tests)
            elif method == 'post' and is_upload:
                build_payload_and_append(method, url, is_upload,
                                         query_name, self._file_upload_tests)

        return method_url_is_upload_and_payloads

    def detect(self):
        """Return a list of XSS objects representing found xss
        on the scrapped website."""
        base_url = self._scrapped_website.url
        found_xss_list = []
        for method, url, is_upload, payload in self.attack_information:
            if self.web_io.was_request_accepted(url, method, is_upload, payload):
                xss_found = XSS(base_url, payload, method)
                found_xss_list.append(xss_found)
        return found_xss_list

# scrap = ScrappedWebsite(URL, HTML_STRING)
# xss = XSSDetector(scrap)
# page = requests.get('https://xss-game.appspot.com/level1/frame')
# print(page.content)
# soup = beautiful_soup(page.content, 'html.parser')
# for form in soup.find_all('form'):
