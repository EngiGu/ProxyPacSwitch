import json
import os
import sys
import re
import argparse
from subprocess import call, getstatusoutput
from http.server import BaseHTTPRequestHandler, HTTPServer, CGIHTTPRequestHandler, SimpleHTTPRequestHandler


def test(HandlerClass=BaseHTTPRequestHandler, ServerClass=HTTPServer, protocol="HTTP/1.0", port=8000, bind=""):
    """Test the HTTP request handler class.

    This runs an HTTP server on port 8000 (or the port argument).

    """
    server_address = (bind, port)

    HandlerClass.protocol_version = protocol
    with ServerClass(server_address, HandlerClass) as httpd:
        sa = httpd.socket.getsockname()
        serve_message = "Serving PAC server on {host} port {port} (http://{host}:{port}/) ..."
        print(serve_message.format(host=sa[0], port=sa[1]))
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nKeyboard interrupt received, exiting.")
            sys.exit(0)


class Main:
    def __init__(self):
        self.config_path = "./config.json"
        pass

    def reader(self, path):
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()

    def writer(self, path, content):
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

    def config_handler(self, args):
        config = self.reader(self.config_path)
        config = json.loads(config)
        pac_port = config.get('pac_port', '')  # type: int
        if not pac_port:
            raise SystemExit("please set pac server port! set from config.json or from tips.")

        # read from line first
        ip_port_format = ('^(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.'
                          '(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.'
                          '(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.'
                          '(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\:'
                          '([0-9]|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$')
        if args.proxy:
            proxy_uri = args.proxy.strip()
            print("read from line, proxy_uri:", proxy_uri)
        else:
            proxy_uri = config.get('proxy_uri', '').strip()
            print("read from config.json, proxy_uri:", proxy_uri)
            if not proxy_uri:
                raise SystemExit("config.json proxy uri is empty.")
        print(args.proxy)
        if not re.match(ip_port_format,proxy_uri):
            raise SystemExit("proxy uri format is invalid [example: 1.2.3.4:8000].")

        # deal bat scripts
        self.deal_bat_scripts(pac_port)

        # deal windows proxy pac
        self.deal_pac_file(proxy_uri)

        # set windows proxy pac
        self.set_windows_pac()

        return pac_port

    def deal_bat_scripts(self, pac_port):
        content = """reg add "hkcu\software\microsoft\windows\currentversion\internet settings" /v AutoConfigURL /t REG_SZ /d "--PAC--" /f"""
        content = content.replace('--PAC--',"http://127.0.0.1:%s/pac" % pac_port)
        self.writer('./set_pac.bat', content)

    def deal_pac_file(self, proxy_uri):
        content = self.reader("./pac")
        content = content.replace('--PROXY--', proxy_uri)
        self.writer('./pac', content)

    def set_windows_pac(self):
        code, result = getstatusoutput("chcp 65001 & set_pac.bat")
        if code != 0:
            raise SystemExit('set windows pac failed. result:', result)
        print("set windows pac success.")

    def start_httpserver(self, args, pac_port):
        """
        start pac HTTP server
        """
        # if args.cgi:
        #     handler_class = CGIHTTPRequestHandler
        # else:
        handler_class = SimpleHTTPRequestHandler
        test(HandlerClass=handler_class, port=pac_port, bind='0.0.0.0')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # parser.add_argument('--cgi', action='store_true',
    #                     help='Run as CGI Server')
    # parser.add_argument('--bind', '-b', default='', metavar='ADDRESS',
    #                     help='Specify alternate bind address '
    #                          '[default: all interfaces]')
    # parser.add_argument('port', action='store',
    #                     default=12345, type=int,
    #                     nargs='?',
    #                     help='Specify alternate port [default: 8000]')
    parser.add_argument('proxy', action='store',
                        default="", type=str,
                        nargs='?',
                        help='Specify proxy uri [example: 1.2.3.4:8000]')
    args = parser.parse_args()

    m = Main()
    pac_port = m.config_handler(args)
    m.start_httpserver(args, pac_port)
