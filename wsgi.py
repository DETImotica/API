import logging

import db
import configparser
from werkzeug.exceptions import NotFound
from werkzeug.middleware.dispatcher import DispatcherMiddleware

from api import app, csrf, paranoid, APP_BASE_ENDPOINT, VERSION

def no_app(environ, start_response):
    return NotFound()(environ, start_response)

config = configparser.ConfigParser()
config.read('options.conf')

IURL = config['influxdb']['URL']
IPORT = config['influxdb']['PORT']
IDB = config['influxdb']['DB']
IUSER = config['influxdb']['USER']
IPW = config['influxdb']['PW']

PGURL = config['postgresql']['URL']
PGPORT = config['postgresql']['PORT']
PGDB = config['postgresql']['DB']
PGUSER = config['postgresql']['USER']   
PGPW = config['postgresql']['PW']

config.read(".appconfig")
ck = config['info']['consumer_key']
cs = config['info']['consumer_secret']

app.config['SECRET_KEY'] = config['info']['app_key']
app.config['APPLICATION_ROOT'] = f"/{APP_BASE_ENDPOINT}/{VERSION}"
db.init_dbs(PGURL, PGPORT, PGDB, PGUSER, PGPW, IURL, IUSER, IPW, IPORT, IDB)

csrf.init_app(app)
paranoid.init_app(app)

app.wsgi_app = DispatcherMiddleware(no_app, {f"/{APP_BASE_ENDPOINT}/{VERSION}": app.wsgi_app})

gunicorn_logger = logging.getLogger('gunicorn.access')
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(gunicorn_logger.level)

if __name__ == "__main__":
    app.run(debug=True, port=443, ssl_context=('cert.pem', 'key.pem'))