import tweepy
from tweepy import OAuthHandler

from francomisp.keys import twitter_consumer_key, twitter_consumer_secret, twitter_access_secret, twitter_access_token
from francomisp.utils.tweet_content import TweetContent

class TwitterBot:

    auth = OAuthHandler(twitter_consumer_key, twitter_consumer_secret)
    auth.set_access_token(twitter_access_token, twitter_access_secret)
    api = tweepy.API(auth)

    @staticmethod
    def search():


        max_id = 0
        tweets = []
        list_ids = TwitterBot.api.saved_searches()
        for ListId in list_ids:
            Query = ListId.name
            for page in range(1, 3):
                if page == 1:
                    tweets = TwitterBot.api.search(q=Query, rpp=100,tweet_mode='extended')
                else:
                    tweets = TwitterBot.api.search(q=Query, rpp=100, max_id=max_id,tweet_mode = 'extended')
                for tweet in tweets:
                    yield tweet

    @staticmethod
    def publish_on_tweet(id_tweet):
        tweet = TwitterBot.api.get_status(id_tweet, tweet_mode='extended')
        if tweet:
            return tweet

    @staticmethod
    def extract_url(tweet, twitter_content):
        urls_pasties = [ twitter_content.url_rewrite(url['expanded_url']) for url in tweet.entities['urls']]
        if hasattr(tweet, 'retweeted_status'):
            urls_pasties.extend([twitter_content.url_rewrite(url['expanded_url']) for url in  tweet.retweeted_status.entities['urls']])
        return urls_pasties

