import base64
import re
import logging
import magic

class DecodePasties:

    def __init__(self, content):
            self.content = content
            self.content_decoded = None
            self.regex_binary = re.compile(b'[0-1]*')
            self.state_machine = {}

    def decode_base64(self):
        try:
            b64_decoded = base64.b64decode(self.content)
            self.content_decoded = b64_decoded
            self.state_machine['encoding'] = {'base64': True}

        except Exception as e:
            logging.ERROR('Error decoding bas64 %s' % e)

    def decode_binary(self):

        if self.regex_binary.match(self.content):
            self.content_decoded = bytes(''.join([chr(int(self.content[i:i + 8], 2))
                                                  for i in range(0, len(self.content), 8)]).encode())
            self.state_machine['encoding'] = {'binary': True}

    def is_pe(self):
        if magic.from_buffer(self.content_decoded) == 'MS-DOS executable':
            self.state_machine['magic'] = {'pe': True}

    def is_elf_64(self):
        if magic.from_buffer(self.content_decoded) == 'ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)':
            self.state_machine['magic'] = {'elf': True}
