#!/usr/bin/python3
# coding=utf-8

import tweepy
from tweepy import OAuthHandler
import re

from francomisp.core import twitter_bot
from francomisp.core.misp_import import MispImport
from francomisp.core.twitter_bot import TwitterBot
from francomisp.keys import misp_url, misp_key, misp_verifycert
from pymisp import PyMISP
import requests
from francomisp.core.twitter_bot import TwitterBot

# ~ from iocp import Parser
from francomisp.utils.decode_pasties import DecodePasties
from francomisp.utils.tweet_content import TweetContent


def MispPopulate(IocUrl, Tweet):
    Event = ""
    Content = ""
    if IocUrl:
        MispObj = PyMISP(misp_url, misp_key, misp_verifycert, 'json', debug=False)
        Search = MispObj.search_all(IocUrl)
        if not Search['response']:
            try:
                Content = requests.get(IocUrl, verify=False).text.encode('ascii', 'ignore').decode('ascii')
            except:
                print("nope")

            if Content:
                Event = MispObj.new_event(distribution=0, info=Tweet.text, analysis=0, threat_level_id=1)
                Text = MispObj.add_named_attribute(event=Event, type_value="text", category="External analysis",
                                                   value=Tweet.text)
                Text = MispObj.add_named_attribute(event=Event, type_value="url", category="External analysis",
                                                   value=IocUrl)
                TweetId = MispObj.add_named_attribute(event=Event, type_value="twitter-id", category="Social network",
                                                      value=Tweet.id)
                Text = MispObj.add_named_attribute(event=Event, type_value="text", category="External analysis",
                                                   value=Content)
                Event = str(Event['Event']['id'])
                ContentToMisp = MispObj.freetext(event_id=Event, string=Content, adhereToWarninglists=True)
        else:
            print("Already exist in Misp")

    return Event


def main():
    data_by_id = {}
    tweet_content = TweetContent()
    misp_import = MispImport()
    for tweet in TwitterBot.search():
        data_by_id[tweet.id] = {'tweet': tweet,'urls_pasties':TwitterBot.extract_url(tweet, tweet_content)}

    data_to_push = {}

    for id, data in data_by_id.items():
        if not id in data_to_push:
            text_tweet = data['tweet'].full_text
            if hasattr(data['tweet'], 'retweeted_status'):
                text_tweet = data['tweet'].retweeted_status.full_text

            data_to_push[id] = {'tweet_text': text_tweet,'data':[], 'urls':  [url['expanded_url'] for url in data['tweet'].entities['urls']]
                                ,'url_tweet': 'https://twitter.com/%s/status/%s'% (data['tweet'].user.screen_name,id)}

        for url in data['urls_pasties']:
            if url:
                decode_pastie = DecodePasties()
                decode_pastie.retrieve_pasties(url)
                decode_pastie.decode()
                data_to_push[id]['data'].append(decode_pastie)
    misp_import.import_data(data_to_push)


if __name__ == '__main__':
    main()