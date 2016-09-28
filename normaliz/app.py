import os, sys
from traceback import format_exc
from flask import Flask
from flask.ext import restful
from werkzeug.contrib.fixers import ProxyFix
from normaliz.components.common import logger, cfg
#from normaliz.resources import ( MxheroResource, DomainResource )

try:
  app = Flask(__name__)

  api = restful.Api(app)
  # load endpoints
  #api.add_resource(MxheroResource, '/mxhero/<mxhero>')
  #api.add_resource(DomainResource, '/mxhero/<mxhero>/domain/<domain_name>')
  #api.add_resource(AppsResource, '/mxhero/<mxhero>/apps/<app_name>')


except KeyError, e:
  print 'Could not find environment variable', e
  sys.exit(1)
except Exception, e:
  print 'Error doing the initial config: %s\n%s' % (e, format_exc())
  sys.exit(1)

app.wsgi_app = ProxyFix(app.wsgi_app)

if __name__ == '__main__':
  try:
    app.run(host='0.0.0.0', port=8080, debug=True)
  except Exception, e:
    print 'Error starting web app: %s' % e