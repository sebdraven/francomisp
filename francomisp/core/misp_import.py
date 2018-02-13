from hashlib import sha256
from io import BytesIO

from pymisp import PyMISP

from francomisp.keys import misp_url, misp_key, misp_verifycert
from pymisp.tools import make_binary_objects
class MispImport:

    def __init__(self):
        self.api = PyMISP(misp_url, misp_key, misp_verifycert, 'json', debug=False)
        self.response = None

    def import_data(self, data_to_push):
        for k, data in data_to_push.items():

            if not self.is_already_present(data['url_tweet']):

                event = self.api.new_event(distribution=0, info=data['url_tweet'], analysis=0, threat_level_id=1)
                self.api.add_named_attribute(event=event,type_value='url', category='External analysis',
                                             value=data['url_tweet'])
                self.api.add_named_attribute(event=event, type_value='text', category='External analysis',
                                    value=data['tweet_text'])
                self.api.add_named_attribute(event=event, type_value="twitter-id", category="Social network",
                                    value=k)

                for url in data['urls']:
                    self.api.add_named_attribute(event=event, type_value='url', category="External analysis", value=url)

                self.api.freetext(event_id=event['Event']['id'], string=data['tweet_text'], adhereToWarninglists=True)
                for d in data['data']:

                    if 'magic' in d.state_machine and d.state_machine['magic']['pe']:
                        hash_algo = sha256()
                        hash_algo.update(d.content_decoded)
                        self.api.add_named_attribute(event=event, type_value='sha256', category='Payload delivery',
                                                     value=hash_algo.hexdigest())
                        self.add_object(event,d.content_decoded,hash_algo.hexdigest())
                    elif 'magic' in d.state_machine and d.state_machine['magic']['elf']:
                        self.api.add_object(event['Event']['id'], 13, d.content_decoded)
                    else:
                        self.api.freetext(event_id=event['Event']['id'], string=d.content_decoded.decode(),adhereToWarninglists=True)
                        self.api.add_named_attribute(event=event, type_value='text', category='External analysis',
                                                     value=d.content_decoded.decode())

    def is_already_present(self, url_tweet):
        response = self.api.search(values=[url_tweet])
        self.response = response
        return bool(response['response'])

    def add_object(self,event,data,filename):
        obj = make_binary_objects(pseudofile=BytesIO(data), filename=filename)
        self.api.add_object(event['Event']['id'], 28, obj[1])