#!/usr/bin/python3
# coding=utf-8

import tweepy
from tweepy import OAuthHandler
import re

from francomisp.core import twitter_bot
from francomisp.core.twitter_bot import TwitterBot
from francomisp.keys import misp_url, misp_key, misp_verifycert
from pymisp import PyMISP
import requests
from francomisp.core.twitter_bot import TwitterBot

# ~ from iocp import Parser
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


def ContentParse(Tweet, MispContent):
    from subprocess import check_output
    import requests
    ParsedIoc = []
    Content = ""
    MispContent['ContentToMisp'] = "test"
    for url in Tweet.entities['urls']:
        urlToTest = url['expanded_url']
        urlToTest = UrlRewrite(urlToTest)
        if urlToTest:
            ContentObj = requests.get(urlToTest)
            print(urlToTest)
            try:
                MispContent['ContentToMisp'] = ContentObj.text
                try:
                    print(urlToTest)
                    for JsonIoc in check_output(["iocp", "-i", "txt", "-o", "json", urlToTest], stdin=None,
                                                stderr=None).splitlines():
                        ParsedIoc.append(JsonIoc.decode('UTF-8'))
                except:
                    print(" ")
            except:
                MispContent['ContentToMisp'] = ""
        else:
            MispContent['ContentToMisp'] = ""

    MispContent['IocList'] = ParsedIoc
    return MispContent


def main():
    urls_by_id = {}
    tweet_content = TweetContent()
    for tweet in TwitterBot.search():
        urls_by_id[tweet.id] = TwitterBot.extract_url(tweet)

    for k,v in urls_by_id.items():
        v['urls'] = [tweet_content.url_rewrite(url) for url in v['urls']]
        urls_by_id[k] = v
        pass
    pass

if __name__ == '__main__':
    main()