#!/usr/bin/python3

from francomisp.core.misp_import import MispImport
from francomisp.core.twitter_bot import TwitterBot
from francomisp.utils.decode_pasties import DecodePasties
from francomisp.utils.tweet_content import TweetContent


def main():
    data_by_id = {}
    tweet_content = TweetContent()
    misp_import = MispImport()
    for tweet in TwitterBot.search():
        data_by_id[tweet.id] = {'tweet': tweet, 'urls_pasties': TwitterBot.extract_url(tweet, tweet_content),
                                'retweet': False}

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

        for url in data['urls_pasties']:
            if url:
                decode_pastie = DecodePasties()
                decode_pastie.retrieve_pasties(url)
                decode_pastie.decode()
                data_to_push[id]['data'].append(decode_pastie)
    misp_import.import_data(data_to_push)


if __name__ == '__main__':
    main()
