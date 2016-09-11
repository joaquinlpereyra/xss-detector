from models.models import URL, XSS, ScrappedWebsite, XSSDetector
from utils.utils import WebIO
import requests
import unittest

class TestURL(unittest.TestCase):
    example_url = "http://example.com/path?query=myquery#4"
    example_url_2 = "https://example.com/path?query=myquery#9"
    example_url_3 = "http://example.com/path?another_query=4"
    example_relative_url = "/relative_path/at/path"

    def test_standarize_absolute_url(self):
        url = URL(TestURL.example_url)
        self.assertEqual(url.netloc, "example.com")
        self.assertEqual(url.path, "/path")
        self.assertEqual(url.scheme, "http")
        self.assertEqual(url.query, "query=myquery")

    def test_standarize_relative_url(self):
        gotten_from = URL(TestURL.example_url)
        url = URL(TestURL.example_relative_url, gotten_from=gotten_from)
        self.assertEqual(url.netloc, "example.com")
        self.assertEqual(url.path, "/relative_path/at/path")
        self.assertEqual(url.query, '')

    def test_url_equality(self):
        self.assertEqual(URL(TestURL.example_url), URL(TestURL.example_url_2))
        self.assertNotEqual(URL(TestURL.example_url), URL(TestURL.example_url_3))

class TestScrappedWebsite(unittest.TestCase):
    website = "https://google-gruyere.appspot.com/201813828985/"
    website_as_string = requests.get(website, cookies={'GRUYERE': '58850990|c||author', 'GRUYERE_ID': '201813828985'}).text
    scrapped_website = ScrappedWebsite(URL(website), website_as_string)

    another_website = 'https://xss-game.appspot.com/level1/frame'
    another_website_as_string = requests.get(another_website).text
    another_scrapped_website = ScrappedWebsite(URL(another_website), another_website_as_string)

    def test_get_unique_relevant_links(self):
        links = {URL('https://google-gruyere.appspot.com/201813828985/snippets.gtl'),
                 URL('https://google-gruyere.appspot.com/201813828985/newsnippet.gtl'),
                 URL('https://google-gruyere.appspot.com/201813828985/upload.gtl'),
                 URL('https://google-gruyere.appspot.com/201813828985/editprofile.gtl'),
                 URL('https://google-gruyere.appspot.com/201813828985/logout'),
                 URL('https://google-gruyere.appspot.com/201813828985/snippets.gtl?uid=cheddar'),
                 URL('https://google-gruyere.appspot.com/201813828985/snippets.gtl?uid=brie')}

        self.assertEqual(TestScrappedWebsite.scrapped_website.get_unique_relevant_links(), links)

    def test_exposed_inputs(self):
        inputs = [('get', URL(TestScrappedWebsite.another_website), False, 'query'),
                  ('get', URL(TestScrappedWebsite.another_website), False, '')]
        self.assertEqual(TestScrappedWebsite.another_scrapped_website.get_exposed_inputs(), inputs)


class TestXSSDetector(unittest.TestCase):
    xss_detector = XSSDetector(TestScrappedWebsite.another_scrapped_website, WebIO(cookies=None))

    def test_detect(self):
        known_xss = [XSS(URL(TestScrappedWebsite.another_website), {'query': "'<script>alert(122)</script>"}, 'get'),
                     XSS(URL(TestScrappedWebsite.another_website), {'': "'<script>alert(122)</script>"}, 'get')]
        TestXSSDetector.xss_detector._get_tests = ["'<script>alert(122)</script>"]
        TestXSSDetector.xss_detector._post_tests = []
        TestXSSDetector.xss_detector._common_tests = []
        TestXSSDetector.xss_detector._file_upload_tests = []
        TestXSSDetector.xss_detector.attack_information = TestXSSDetector.xss_detector._create_attack_information()
        self.assertEqual(TestXSSDetector.xss_detector.detect(), known_xss)
