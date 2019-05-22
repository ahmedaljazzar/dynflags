class BaseFlagCacheManager:
    def __init__(self):
        self.flag_cache = {}

    def get_cache_for_key(self, key):
        return self.cache.get(key)

    def set_cache_for_key(self, key, value):
        self.cache[key] = value
