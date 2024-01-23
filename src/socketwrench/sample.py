import logging
from socketwrench import Server as SocketWrench, methods
from pathlib import Path

from socketwrench.tags import private, post, put, patch, delete

logging.basicConfig(level=logging.DEBUG)


class Sample:
    def hello(self):
        """A simple hello world function."""
        return "world"

    @methods("GET", "POST")  # do to the label, this will be accessible by both GET and POST requests
    def hello2(self, method):
        """A simple hello world function."""
        return "world"

    def _unserved(self):
        """This function will not be served."""
        return "this will not be served"

    @private
    def unserved(self):
        """This function will not be served."""
        return "this will not be served"

    @post
    def post(self, name):
        """This function will only be served by POST requests."""
        return f"hello {name}"

    @put
    def put(self, name):
        """This function will only be served by PUT requests."""
        return f"hello {name}"

    @patch
    def patch(self, name):
        """This function will only be served by PATCH requests."""
        return f"hello {name}"

    @delete
    def delete(self, name):
        """This function will only be served by DELETE requests."""
        return f"hello {name}"

    def echo(self, *args, **kwargs):
        if not args and not kwargs:
            return
        if args:
            if len(args) == 1:
                return args[0]
            return args
        elif kwargs:
            return kwargs
        return args, kwargs

    def string(self):
        return "this is a string"

    def html(self):
        return "<h1>hello world</h1><br><p>this is a paragraph</p>"

    def json(self):
        return {"x": 6, "y": 7}

    def file(self):
        return Path(__file__)

    def add(self, x: int, y: int):
        return x + y

    def client_addr(self, client_addr):
        return client_addr

    def headers(self, headers):
        return headers

    def query(self, query, *args, **kwargs):
        return query

    def body(self, body):
        return body

    def method(self, method):
        return method

    def route(self, route):
        return route

    def request(self, request):
        return request

    def everything(self, request, client_addr, headers, query, body, method, route, full_path):
        d = {
            "request": request,
            "client_addr": client_addr,
            "headers": headers,
            "query": query,
            "body": body,
            "method": method,
            "route": route,
            "full_path": full_path,
        }
        for k, v in d.items():
            print(k, v)
        return d


if __name__ == '__main__':
    s = Sample()
    SocketWrench(s, serve=True)
