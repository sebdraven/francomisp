import tweepy
from tweepy import OAuthHandler

from francomisp.keys import twitter_consumer_key, twitter_consumer_secret, twitter_access_secret, twitter_access_token


class TwitterBot:

    @staticmethod
    def search():

        auth = OAuthHandler(twitter_consumer_key, twitter_consumer_secret)
        auth.set_access_token(twitter_access_token, twitter_access_secret)
        api = tweepy.API(auth)
        max_id = 0
        tweets = []
        list_ids = api.saved_searches()
        for ListId in list_ids:
            Query = ListId.name
            for page in range(1, 3):
                if page == 1:
                    tweets = api.search(q=Query, rpp=100)
                else:
                    tweets = api.search(q=Query, rpp=100, max_id=max_id)
                for tweet in tweets:
                    yield tweet

    @staticmethod
    def extract_url(tweet):
        url_by_id = {'urls': [ url['expanded_url'] for url in tweet.entities['urls']], 'Tweet': tweet}

        if url_by_id:
            return url_by_id
