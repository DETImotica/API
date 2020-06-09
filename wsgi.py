import configparser
import logging

from werkzeug.exceptions import NotFound
from werkzeug.middleware.dispatcher import DispatcherMiddleware

from api import app, csrf, APP_BASE_ENDPOINT, VERSION
from caching import cache, session_cache

def app_not_found(env, resp):
    return NotFound()(env, resp)

config = configparser.ConfigParser()

config.read(".appconfig")

app.config['SECRET_KEY'] = config['info']['app_key']
app.config['APPLICATION_ROOT'] = f"/{APP_BASE_ENDPOINT}/{VERSION}"

csrf.init_app(app)
#paranoid.init_app(app)
cache.init_app(app)
session_cache.init_app(app)

app.wsgi_app = DispatcherMiddleware(app_not_found, {f"/{APP_BASE_ENDPOINT}/{VERSION}": app.wsgi_app})

#gunicorn_logger = logging.getLogger('gunicorn.access')
#app.logger.handlers = gunicorn_logger.handlers
#app.logger.setLevel(gunicorn_logger.level)

if __name__ == "__main__":
    app.run(debug=True, port=555, ssl_context=('cert.pem', 'key.pem'))
