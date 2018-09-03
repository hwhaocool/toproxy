#!/usr/bin/env python
#coding:utf-8

import logging
import os
import re
import socket
from urlparse import urlparse
# from urllib.parse import urlparse

import tornado.httpserver
import tornado.ioloop
import tornado.iostream
import tornado.web
import tornado.httpclient
from tornado.httputil import HTTPHeaders

import time
import json
import simplejson
import pbjson

from SignTool import SignTools

import sys
sys.path.append('./protobuf')
import SkmrMain_pb2

logging.basicConfig(
    level = logging.INFO,
    format = '[%(asctime)s] - [%(filename)s] [%(levelname)s] - %(message)s'
    # datefmt = '%Y-%m-%d %A %H:%M:%S',
    )

logger = logging.getLogger(__name__)

class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'PUT', 'POST', 'CONNECT']

    @tornado.web.asynchronous
    def get(self):
        logger.info('Handle %s request to %s', self.request.method, self.request.uri)

        isProtobuf = checkHeaderType(self.request.headers)

        def handle_response(response):
            logger.info("reponse code is %s", response.code)

            if (response.error and not
                    isinstance(response.error, tornado.httpclient.HTTPError)):
                self.set_status(500)
                self.write('Internal server error:\n' + str(response.error))
            else:
                self.set_status(response.code)
                for header in ('Date', 'Cache-Control', 'Server', 'Content-Type', 'Location'):
                    v = response.headers.get(header)
                    if v:
                        self.set_header(header, v)
                v = response.headers.get_list('Set-Cookie')
                if v:
                    for i in v:
                        self.add_header('Set-Cookie', i)
                self.add_header('VIA', 'Toproxy')

                ## 处理响应体
                if response.body:
                    r_b = response.body

                    if isProtobuf:
                        response_body = SkmrMain_pb2.SkmrMsg()
                        response_body.ParseFromString(r_b)
                        self.write(str(response_body))
                    else:
                        self.write(response.body)
            self.finish()

        #远程IP 白名单校验
        client_ip = self.request.remote_ip
        logger.info("remote ip is %s", client_ip)

        ## 处理URL
        if self.request.uri:
            logger.info("URL is %s", self.request.uri)

        ## 处理header
        self.request.headers = generate_header(self.request.headers, isProtobuf)

        #处理body
        body = handle_body(self.request.body, isProtobuf)

        try:
            fetch_request(
                self.request.uri, handle_response,
                method=self.request.method,
                body=body,
                headers=self.request.headers,
                follow_redirects=False,
                allow_nonstandard_methods=True)
        except tornado.httpclient.HTTPError as e:
            logger.error("get , have error %s", e)
            if hasattr(e, 'response') and e.response:
                handle_response(e.response)
            else:
                self.set_status(500)
                self.write('Internal server error:\n' + str(e))
                self.finish()

    @tornado.web.asynchronous
    def post(self):
        return self.get()

    @tornado.web.asynchronous
    def put(self):
        return self.get()

    @tornado.web.asynchronous
    def connect(self):
        logger.info('Start CONNECT to %s', self.request.uri)

        host, port = self.request.uri.split(':')
        client = self.request.connection.stream

        def read_from_client(data):
            upstream.write(data)

        def read_from_upstream(data):
            client.write(data)

        def client_close(data=None):
            if upstream.closed():
                return
            if data:
                upstream.write(data)
            upstream.close()

        def upstream_close(data=None):
            if client.closed():
                return
            if data:
                client.write(data)
            client.close()

        def start_tunnel():
            logger.debug('CONNECT tunnel established to %s', self.request.uri)
            client.read_until_close(client_close, read_from_client)
            upstream.read_until_close(upstream_close, read_from_upstream)
            client.write(b'HTTP/1.0 200 Connection established\r\n\r\n')

        def on_proxy_response(data=None):
            if data:
                first_line = data.splitlines()[0]
                http_v, status, text = first_line.split(None, 2)
                if int(status) == 200:
                    logger.debug('Connected to upstream proxy %s', proxy)
                    start_tunnel()
                    return

            self.set_status(500)
            self.finish()

        def start_proxy_tunnel():
            #upstream.write('Server: Toproxy\r\n')
            upstream.write('CONNECT %s HTTP/1.1\r\n' % self.request.uri)
            upstream.write('Host: %s\r\n' % self.request.uri)
            upstream.write('Proxy-Connection: Keep-Alive\r\n\r\n')
            upstream.read_until('\r\n\r\n', on_proxy_response)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        upstream = tornado.iostream.IOStream(s)

        proxy = get_proxy(self.request.uri)
        if proxy:
            proxy_host, proxy_port = parse_proxy(proxy)
            upstream.connect((proxy_host, proxy_port), start_proxy_tunnel)
        else:
            upstream.connect((host, int(port)), start_tunnel)


def get_proxy(url):
    url_parsed = urlparse(url, scheme='http')
    proxy_key = '%s_proxy' % url_parsed.scheme
    return os.environ.get(proxy_key)


def base_auth_valid(auth_header):
    auth_mode, auth_base64 = auth_header.split(' ', 1)
    assert auth_mode == 'Basic'
    auth_username, auth_password = auth_base64.decode('base64').split(':', 1)
    if auth_username == base_auth_user and auth_password == base_auth_passwd:
        return True
    else:
        return False

def checkHeaderType(old_header):
    '''检查header是否是protobuf'''
    header_type = old_header.get("type")

    #设置数据传输类型
    if "protobuf" == header_type:
        return True
    else:
        return False

def generate_header(old_header, isProtobuf=True):
    """生成签名后的headers"""

    global sign_tool

    user_agent = {
        "version": "4.4",
        "appName": "kanfangriji"
    }

    user_agent_str = json.dumps(user_agent)

    t = time.time()
    timestamp = str(int(round(t * 1000)))
    random_str = "asdf"

    timestamp_str = "%s+%s" % (timestamp, random_str)

    sign_str = timestamp + user_agent_str + random_str

    sign_result = sign_tool.sign(sign_str)
    
    new_header = HTTPHeaders()

    new_header.add("nonce", "6906")
    new_header.add("User-Agent", user_agent_str)
    new_header.add("x-trace-id", "87c7d310-a1e6-11e8-9127-db5d4669379a")
    new_header.add("X-Token", "token-fsf359jtys")

    new_header.add("Timestamp", timestamp_str)
    new_header.add("Signature", sign_result)

    auth_token = old_header.get("Authorization")

    #设置自定义token
    if auth_token:
        new_header.add("Authorization", auth_token)

    #设置数据传输类型
    if isProtobuf:
        new_header.add("Accept", "application/x-protobuf")
        new_header.add("Content-Type", "application/x-protobuf")
    else:
        new_header.add("Accept", "application/json;charset=UTF-8")
        new_header.add("Content-Type", "application/json;charset=UTF-8")

    return new_header

def handle_body(body, isProtobuf=True):
    """处理body"""
    if not body:
        body = None

    print type(body)

    if isProtobuf:
        #转换json为protobuf
        body_json = simplejson.loads(body)
        print type(body_json)

        logger.info("body is %s", str(body_json)) 

        a1 = pbjson.dict2pb(SkmrMain_pb2.SkmrMsg, body_json)
        logger.info("SkmrMsg is %s", str(a1))
        body = a1.SerializeToString()

    return body

def parse_proxy(proxy):
    proxy_parsed = urlparse(proxy, scheme='http')
    return proxy_parsed.hostname, proxy_parsed.port


def match_white_iplist(clientip):
    if clientip in white_iplist:
        return True
    if not white_iplist:
        return True
    return False


def shield_attack(header):
    """客户端攻击"""
    if re.search(header, 'ApacheBench'):
        return True
    return False


def fetch_request(url, callback, **kwargs):
    req = tornado.httpclient.HTTPRequest(url, **kwargs)
    client = tornado.httpclient.AsyncHTTPClient()
    client.fetch(req, callback)


def run_proxy(port, pnum=1, start_ioloop=True):
    import tornado.process
    app = tornado.web.Application([
        (r'.*', ProxyHandler),
    ])

    if pnum > 200 or pnum < 0:
        raise("process num is too big or small")
    if pnum == 1:
        app.listen(port)
        ioloop = tornado.ioloop.IOLoop.instance()
        if start_ioloop:
            ioloop.start()
    else:
        sockets = tornado.netutil.bind_sockets(port)
        tornado.process.fork_processes(pnum)
        server = tornado.httpserver.httpserver(app)
        server.add_sockets(sockets)
        tornado.ioloop.ioloop.instance().start()


if __name__ == '__main__':
    import argparse
    white_iplist = []
    parser = argparse.ArgumentParser(description='''python -m toproxy/proxy  -p 9999 -w 127.0.0.1,8.8.8.8 -d fiddler''')

    parser.add_argument('-p', '--port', help='tonado proxy listen port', action='store', default=9999)
    parser.add_argument('-w', '--white', help='white ip list ---> 127.0.0.1,215.8.1.3', action='store', default=[])
    parser.add_argument('-d', '--debug', help='Debug Type , fiddler', action='store', default=None)

    #线程数
    parser.add_argument('-f', '--fork', help='fork process to support', action='store', default=1)
    args = parser.parse_args()

    if not args.port:
        parser.print_help()

    port = int(args.port)
    white_iplist = args.white

    dbeug_type = args.debug

    print ("Starting HTTP proxy on port %d" % port)

    global sign_tool
    sign_tool = SignTools()

    pnum = int(args.fork)
    run_proxy(port, pnum)
