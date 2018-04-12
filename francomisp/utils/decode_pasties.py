import base64
import re
import logging
import magic
import requests


class DecodePasties:

    def __init__(self):
            self.content = None
            self.content_decoded = None
            self.regex_binary = re.compile(b'[0-1]*')
            self.state_machine = {}
            self.url_scrap_pastie = 'https://pastebin.com/api_scrape_item.php?i=%s'
            self.url_scrap_meta = 'https://pastebin.com/api_scrape_item_meta.php?i=%s'

    def __decode_base64(self):
        try:
            b64_decoded = base64.b64decode(self.content)
            assert base64.b64encode(b64_decoded) == self.content
            self.content_decoded = b64_decoded
            self.state_machine['encoding'] = {'base64': True}
        except Exception as e:
            logging.error('Error decoding bas64 %s' % e)

    def __decode_binary(self):


            try:
                if self.regex_binary.match(self.content):
                    self.content_decoded = bytes(''.join([chr(int(self.content[i:i + 8], 2))
                                                      for i in range(0, len(self.content), 8)]).encode())
                    self.state_machine['encoding'] = {'binary': True}
            except Exception as e:
                logging.error('Error decoding binary %s' %e)

    def __is_pe(self):
        try:
            if magic.from_buffer(self.content_decoded) in ['MS-DOS executable',
                                                           'PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows']:
                self.state_machine['magic'] = {'pe': True}
        except Exception as e:
            logging.error('is not pe %s' % e)

    def __is_elf_64(self):
        try:
            if magic.from_buffer(self.content_decoded) == 'ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)':
                self.state_machine['magic'] = {'elf': True}
        except Exception as e:
            logging.error('is not magic %s' % e)

    def retrieve_pasties(self, url):
        token = url.split('/')
        id_pastie = token[len(token)-1]
        r = requests.get(self.url_scrap_pastie % id_pastie, stream=True)
        if r.status_code == 200:
            self.content = r.content
            self.content_decoded = self.content

    def decode(self):

        self.__decode_base64()
        self.__decode_binary()
        self.__is_pe()
        self.__is_elf_64()