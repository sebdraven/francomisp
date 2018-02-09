import re


class TweetContent:

    def __init__(self):
        self.re_pastebin = re.compile(r'(https:\/\/pastebin\.com\/[a-z0-9A-Z]{8})')
        self.re_pastebin2 = re.compile(r'(https:\/\/pastebin\.com\/raw\/[a-z0-9A-Z]{8})')
        self.re_ghostbin = re.compile(r'(https:\/\/ghostbin.com\/paste\/[a-z0-9]{5})')
        self.re_alienvaut_url = re.compile(r'(https://otx.alienvault.com/pulse/[a-z0-9]{24})')

    def url_rewrite(self, url):

        rewrite_pastebin_url = self.re_pastebin.findall(url)
        rewrite_pastebin_url2 = self.re_pastebin2.findall(url)
        rewrite_alienvault_url = self.re_alienvaut_url.findall(url)
        rewrite_url = ''

        if rewrite_pastebin_url:
            rewrite_url = re.sub(r"(pastebin\.com\/)", "pastebin.com/raw/", rewrite_pastebin_url[0])
        elif rewrite_pastebin_url2:
            rewrite_url = rewrite_pastebin_url2[0]
        elif rewrite_alienvault_url:
            rewrite_url = rewrite_alienvault_url[0].replace('pulse', 'pulses')
            rewrite_url = re.sub(r"$", "/export?format=csv", rewrite_url, 0)
        return rewrite_url
