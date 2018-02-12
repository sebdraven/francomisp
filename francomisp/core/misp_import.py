from pymisp import PyMISP

from francomisp.keys import misp_url, misp_key, misp_verifycert

class MispImport:

    def __init__(self):
        self.api = PyMISP(misp_url, misp_key, misp_verifycert, 'json', debug=False)
        self.response = None

    def import_data(self, data_to_push):
        for k, data in data_to_push.items():
            if not self.is_already_present(data['url_tweet']):
                event = self.api.new_event(distribution=0, info=data['url_tweet'], analysis=0, threat_level_id=1)
                self.api.add_named_attribute(event=event, type_value="text", category="External analysis",
                                    value=data['tweet_text'])
                self.api.add_named_attribute(event=event, type_value="twitter-id", category="Social network",
                                    value=k)

                for url in data['urls']:
                    self.api.add_named_attribute(event=event, type_value='url', category="External analysis", value=url)

                self.api.freetext(event_id=event['Event']['id'], string=data['tweet_text'], adhereToWarninglists=True)
                for d in data['data']:

                    if 'magic' in d.state_machine and d.state_machine['magic']['pe']:
                        self.api.add_object(event['Event']['id'],28, d.content_decoded)
                    elif 'magic' in d.state_machine and d.state_machine['magic']['elf']:
                        self.api.add_object(event['Event']['id'], 13, d.content_decoded)
                    else:
                        self.api.freetext(event_id=event['Event']['id'], string=d.content_decoded.decode(),adhereToWarninglists=True)


    def is_already_present(self, url_tweet):
        response = self.api.search(values=[url_tweet])
        self.response = response
        return bool(response['response'])
