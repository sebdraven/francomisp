from redis import StrictRedis


class Caching:

    def __init__(self):
        self.red = StrictRedis(db=9)

    def translate(self,tweet_id):
        return self.red.get(tweet_id)

    def caching(self, tweet_id, eid):
        self.red.set(tweet_id, eid)
