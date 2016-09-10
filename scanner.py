import requests
import threading
import queue
import argparse
import json
from logs.logger import logger
from persistence.db_manager import DBManager
from models.models import ScrappedWebsite, XSSDetector
from utils.utils import SafeIO

websites_to_visit = queue.Queue()
visited_websites = []
class Worker(threading.Thread):
    def __init__(self, lock, web_io, initial_url):
        threading.Thread.__init__(self)
        self.daemon = True
        self.lock = lock
        self.web_io = web_io
        self.initial_url = initial_url

    def run(self):
        self.db_manager = DBManager(self.initial_url)
        while True:
            self.safely_continously_check_websites_for_xss()

    def safely_continously_check_websites_for_xss(self):
        while True:
            try:
                self.check_website_for_xss()
            except:
                logger.exception("Unhandled exception while processing a website."
                                 "Will continue with next website on queue.")
                continue
            finally:
                websites_to_visit.task_done()

    def check_website_for_xss(self):
        url = websites_to_visit.get()
        if url in set(visited_websites):
            logger.warning("URL {0} was already visited so it wont be processed".format(url))
            return False
        logger.info("Processing URL {0}".format(url))
        visited_websites.append(url)
        website_as_string = self.web_io.get_website_as_string(url)
        if website_as_string:
            scrapped_website = ScrappedWebsite(url, website_as_string)
            xss_found = self.extract_xss_from_website(scrapped_website)
            self.write_xss_to_db(xss_found)
            self.append_new_websites(scrapped_website)
        return True

    def extract_xss_from_website(self, scrapped_website):
        xss_detector = XSSDetector(scrapped_website, self.web_io)
        xss_found = xss_detector.detect()
        return xss_found

    def append_new_websites(self, scrapped_website):
        new_links = scrapped_website.get_unique_relevant_links()
        for link in new_links:
            websites_to_visit.put(link)

    def write_xss_to_db(self, xss_list):
        with self.lock:  #sqlite is fine with reading by multiple threads, not writing
            self.db_manager.write_xss_list_to_db(xss_list)

def parse_args():
    description_string = ("Take an initial URL and check it for XSS. "
                         "Will also recursively check the links inside that "
                         "URL and check them too for XSS. Takes an "
                         "initial URL and amount of threads as mandatory "
                         "parameters and cookies as an optional parameter")
    parser = argparse.ArgumentParser(description=description_string)
    parser.add_argument("initial_url", type=str, help="The seed URL (NOT URI) for the program.")
    parser.add_argument("threads", type=int, help="Amount of threads to be used.")
    parser.add_argument("--cookies", type=str, default=None,
                        help=("You can specify cookies to be used in the requests. "
                            "You must provide it as a json which lools like this: \n "
                            "'{cookie1: value1, cookie2: value2, ...} \n"))
    return parser.parse_args()

def process_cookies(json_cookie_string):
    if json_cookie_string is None:
        return json_cookie_string
    try:
        return json.loads(json_cookie_string)
    except json.decoder.JSONDecodeError:
        logger.exception("You provided a non-valid string for cookies.")
        raise

def main():
    args = parse_args()
    web_io = SafeIO(process_cookies(args.cookies))
    websites_to_visit.put(args.initial_url)
    threads = []
    lock = threading.Lock()
    for t in range(args.threads):
        w = Worker(lock, web_io, args.initial_url)
        threads.append(w)
        w.start()
    websites_to_visit.join()
    print("Progam is finished! Check the database on persistence/xss.db.")
    return None

if __name__ == '__main__':
    main()
