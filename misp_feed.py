#!/usr/bin/python3
import sys
import logging

import os

from francomisp.core.misp_import import MispImport
from francomisp.core.twitter_bot import TwitterBot
from francomisp.utils.decode_pasties import DecodePasties
from francomisp.utils.tweet_content import TweetContent

def create_logger():
    logger = logging.getLogger('FrancoMisp')
    logger.setLevel(logging.DEBUG)

    hLogger = logging.FileHandler(os.path.join(os.path.dirname(__file__),   'francomisp.log'))
    hLogger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    hLogger.setFormatter(formatter)
    logger.addHandler(hLogger)
    return logger


def main():

    data_by_id = {}
    tweet_content = TweetContent()

    logger = create_logger()

    misp_import = MispImport(logger)

    logger.debug('Process is started')

    for tweet in TwitterBot.search():
        data_by_id[tweet.id] = {'tweet': tweet, 'urls_pasties': TwitterBot.extract_url(tweet, tweet_content),
                                'retweet': False}

    logger.debug('Twitter searches are finished ')

    data_to_push = {}

    for id, data in data_by_id.items():
        if not id in data_to_push:
            text_tweet = data['tweet'].full_text
            if hasattr(data['tweet'], 'retweeted_status'):
                text_tweet = data['tweet'].retweeted_status.full_text
                data['retweet'] = True
            data_to_push[id] = {'tweet_text': text_tweet, 'data': [],
                                'urls': [url['expanded_url'] for url in data['tweet'].entities['urls']]
                , 'url_tweet': 'https://twitter.com/%s/status/%s' % (data['tweet'].user.screen_name, id),
                                'retweet': data['retweet'],'tags': [ h['text'] for h in data['tweet'].entities['hashtags']]}
        logger.info('Start to download data on pastebin')
        for url in data['urls_pasties']:
            if url:
                decode_pastie = DecodePasties()
                decode_pastie.retrieve_pasties(url)
                decode_pastie.decode()
                data_to_push[id]['data'].append(decode_pastie)
    logger.info('Import data in MISP')
    all_events = misp_import.import_data(data_to_push)
    logger.info('All Events are created %s' % all_events)


def push_one_event(url):
    tweet_content = TweetContent()
    misp_import = MispImport()
    data_by_id ={}
    id_tweet = url.split('/')[-1:][0]
    tweet = TwitterBot.publish_on_tweet(id_tweet)

    data_by_id[tweet.id] = {'tweet': tweet, 'urls_pasties': TwitterBot.extract_url(tweet, tweet_content),
                            'retweet': False}

    data_to_push = {}

    data_to_push = {}

    for id, data in data_by_id.items():
        if not id in data_to_push:
            text_tweet = data['tweet'].full_text
            if hasattr(data['tweet'], 'retweeted_status'):
                text_tweet = data['tweet'].retweeted_status.full_text
                data['retweet'] = True
            data_to_push[id] = {'tweet_text': text_tweet, 'data': [],
                                'urls': [url['expanded_url'] for url in data['tweet'].entities['urls']]
                , 'url_tweet': 'https://twitter.com/%s/status/%s' % (data['tweet'].user.screen_name, id),
                                'retweet': data['retweet'],
                                'tags': [h['text'] for h in data['tweet'].entities['hashtags']]}

        for url in data['urls_pasties']:
            if url:
                decode_pastie = DecodePasties()
                decode_pastie.retrieve_pasties(url)
                decode_pastie.decode()
                data_to_push[id]['data'].append(decode_pastie)
    misp_import.import_data(data_to_push)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        url = sys.argv[1]
        push_one_event(url)
    else:
        main()
