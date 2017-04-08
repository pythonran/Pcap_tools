import os

import sys

from tornado.options import options, define, parse_command_line

import django.core.handlers.wsgi

import tornado.httpserver

import tornado.ioloop

import tornado.web

import tornado.wsgi


_HERE = os.path.dirname(os.path.abspath(__file__))

sys.path.append(_HERE)

sys.path.append(os.path.join(_HERE, '..'))

sys.path.append(os.path.join(_HERE, '../contrib'))

os.environ['DJANGO_SETTINGS_MODULE'] = "analyzer.settings"


import django
django.setup()
#print "asdf"
def main(port):

 wsgi_app = tornado.wsgi.WSGIContainer(

     django.core.handlers.wsgi.WSGIHandler())

 tornado_app = tornado.web.Application(

     [('.*', tornado.web.FallbackHandler, dict(fallback=wsgi_app)),

     ])
 
 server = tornado.httpserver.HTTPServer(tornado_app)

 server.listen(port,address="127.0.0.1")

 tornado.ioloop.IOLoop.instance().start()

if __name__ == '__main__':

 main(int(sys.argv[1]))
