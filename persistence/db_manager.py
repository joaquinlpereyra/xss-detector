import dataset

class DBManager:
    def __init__(self, url):
        self.table_name = url

    def write_xss_list_to_db(self, xss_list):
        with dataset.connect('sqlite:///persistence/xss.db') as connection:
            for xss in xss_list:
                data = dict(url=xss.url, payload=xss.payload, method=xss.method)
                connection[self.table_name].insert(data)
