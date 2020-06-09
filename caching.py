from flask_caching import Cache

cache = Cache()
session_cache = Cache(config={'CACHE_DIR': ".app_session_cache/",
                                   'CACHE_DEFAULT_TIMEOUT': 3600*24*30
                                  })