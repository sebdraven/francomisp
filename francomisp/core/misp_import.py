from pymisp import PyMISP

from francomisp.keys import misp_url, misp_key, misp_verifycert


class MispImport:

    def __init__(self,tweet, url):
        self.api = PyMISP(misp_url, misp_key, misp_verifycert, 'json', debug=False)
        self.tweet = tweet
        self.url = url
        self.response = None

    def is_already_present(self):
        response = self.api.search(self.url)
        self.response = response
        return bool(response['response'])