from hashlib import sha256
from io import BytesIO

import requests
from pymisp import PyMISP

from francomisp.core.caching import Caching
from francomisp.keys import misp_url, misp_key, misp_verifycert
from pymisp.tools import make_binary_objects


class MispImport:

    def __init__(self, logger):
        self.api = PyMISP(misp_url, misp_key, misp_verifycert, 'json', debug=False)
        self.response = None
        self.logger = logger
        self.caching = Caching()

    def import_data(self, data_to_push):
        all_events = []
        for k, data in data_to_push.items():

            if not self.is_already_present(data['url_tweet']):

                if data['retweet']:
                    self.logger.info('RT %s %s ' % (data['retweet_id'],data['url_tweet']))
                    eid = self.caching.translate(data['retweet_id'])
                    self.logger.info('translate found %s %s' % (eid,data['retweet_id']))
                    if eid:
                        event = self.api.get(int(eid))
                    else:
                        res = self.api.search(values=data['retweet_id'], type_attribute='twitter-id')
                        if res['response']:
                            event = res['response'][0]
                        else:
                            self.logger.error('Event not found tweet %s ' % data['retweet_id'])
                            continue

                    if 'Event' in event:

                        self.logger.info('Event has found %s' % event['Event']['id'] )
                        self.caching.caching(data['retweet_id'], event['Event']['id'])
                        self.api.add_named_attribute(event=event, type_value='url', category='External analysis', value=data['url_tweet'])
                        self.api.add_named_attribute(event=event, type_value="twitter-id", category="Social network",
                                                 value=k)
                        all_tags = [t['name'] for t in event['Event']['Tag']]
                        if not 'toqualify' in all_tags and not 'toenrich' in all_tags:
                            self.api.tag(event['Event']['uuid'], 'topublish')
                    else:
                        self.logger.error('Event not found tweet %s error decode %s' % (data['retweet_id'],event))
                    continue

                elif data['quoted_tweet']:
                    self.logger.info('Tweet quoted %s' % data['quoted_tweet'])
                    eid = self.caching.translate(data['quoted_status_id'])
                    if eid:
                        event = self.api.get(int(eid))
                    else:
                        res = self.api.search(values=data['quoted_status_id'], type_attribute='twitter-id')
                        if res['response']:
                            event = res['response'][0]
                            if 'Event' in event:
                                self.caching.caching(data['quoted_status_id'], event['Event']['id'])
                            else:
                                self.logger.error('Event not found tweet %s ' % data['quoted_status_id'])
                                continue
                        else:
                            self.logger.error('Quoted Tweet not found %s' % data['url_tweet'])
                            continue
                else:
                    event = self.api.new_event(distribution=0, info=data['url_tweet'], analysis=0, threat_level_id=1)
                    self.caching.caching(k, event['Event']['id'])

                self.logger.info('Event create %s' % event['Event']['id'])

                if event:
                    self.add_tags(event, data['tags'])



                    self.api.add_named_attribute(event=event, type_value='url', category='External analysis',
                                                 value=data['url_tweet'])
                    self.logger.info('add url tweet %s at %s' % (data['url_tweet'],event['Event']['id']))
                    self.api.add_named_attribute(event=event, type_value='text', category='External analysis',
                                        value=data['tweet_text'])
                    self.api.add_named_attribute(event=event, type_value="twitter-id", category="Social network",
                                        value=k)

                    for url in data['urls']:
                        self.api.add_named_attribute(event=event, type_value='url', category="External analysis", value=url)
                        self.logger.info('add externals url %s to %s' % (url, event['Event']['id']))

                    self.api.freetext(event_id=event['Event']['id'], string=data['tweet_text'], adhereToWarninglists=True)
                    self.logger.debug('add text %s to %s' % (data['tweet_text'], event['Event']['id']))

                    for d in data['data']:

                        if 'magic' in d.state_machine and d.state_machine['magic']['pe']:
                            hash_algo = sha256()
                            hash_algo.update(d.content_decoded)
                            self.api.add_named_attribute(event=event, type_value='sha256', category='Payload delivery',
                                                         value=hash_algo.hexdigest())
                            self.add_object(event, d.content_decoded, hash_algo.hexdigest())

                            self.add_tags(event,['Malware'])
                            self.logger.info('add malware')

                        elif 'magic' in d.state_machine and d.state_machine['magic']['elf']:
                            self.api.add_object(event['Event']['id'], 13, d.content_decoded)
                        else:
                            try:
                                self.api.freetext(event_id=event['Event']['id'], string=d.content_decoded.decode(),adhereToWarninglists=True)
                                self.api.add_named_attribute(event=event, type_value='text', category='External analysis',
                                                         value=d.content_decoded.decode())
                            except UnicodeDecodeError:
                                self.logger.Error('Error decoding')
                                pass

                self.__remove_shortcut(event)
                all_events.append(event['Event']['id'])
        return all_events


    def is_already_present(self, url_tweet):
        try:
            response = self.api.search(values=[url_tweet])
            self.response = response
            return bool(response['response'])
        except:
            self.logger.error('Error search %s ' % url_tweet)
            return True

    def add_object(self, event, data, filename):
        obj = make_binary_objects(pseudofile=BytesIO(data), filename=filename)
        if obj[1]:
            self.api.add_object(event['Event']['id'], 28, obj[1])

    def add_tags(self,event, tags):
        #self.api.add_tag(event,'OSINT')
        for t in tags:
            self.api.tag(event['Event']['uuid'],t)
        self.api.tag(event['Event']['uuid'], 'OSINT')
        self.api.tag(event['Event']['uuid'], 'tlp:white')
        self.api.tag(event['Event']['uuid'], 'toenrich')

    def __remove_shortcut(self, event):
        self.logger.debug('delete attr function')
        event = self.api.get_event(event['Event']['id'])
        attrs = [attr for attr in event['Event']['Attribute'] if
                 attr['category'] == 'Network activity' and 'https://t.co' in attr['value']]

        for attr in attrs:
            self.logger.debug('try to connect to %s' % attr['value'])
            r = requests.get(attr['value'].replace("'", ""))

            if r.status_code == 200:
                self.api.add_named_attribute(event=event, type_value='url', category='External analysis',
                                value=r.url)

            self.api.delete_attribute(attr['id'])
            self.logger.info('delete attr %s' % attr['id'])
