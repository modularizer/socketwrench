import logging
from pathlib import Path

from socketwrench.tags import private, post, put, patch, delete, route, methods

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
        """Echos back any query or body parameters."""
        if not args and not kwargs:
            return
        if args:
            if len(args) == 1:
                return args[0]
            return args
        elif kwargs:
            return kwargs
        return args, kwargs

    def string(self) -> str:
        """Returns a string response."""
        return "this is a string"

    def html(self) -> str:
        """Returns an HTML response."""
        return "<h1>hello world</h1><br><p>this is a paragraph</p>"

    def json(self) -> dict:
        """Returns a JSON response."""
        return {"x": 6, "y": 7}

    def file(self) -> Path:
        """Returns sample.py as a file response."""
        return Path(__file__)

    def add(self, x: int, y: int):
        """Adds two numbers together."""
        return x + y

    def client_addr(self, client_addr):
        """Returns the client address."""
        return client_addr

    def headers(self, headers) -> dict:
        """Returns the request headers."""
        return headers

    def query(self, query, *args, **kwargs) -> str:
        """Returns the query string."""
        return query

    def body(self, body) -> bytes:
        """Returns the request body."""
        return body

    def method(self, method) -> str:
        """Returns the method."""
        return method

    def get_route(self, route) -> str:
        """Returns the route."""
        return route

    def request(self, request) -> dict:
        """Returns the request object."""
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

    @route("/a/{c}", error_mode="traceback")
    def a(self, b, c=5):
        print(f"calling a with {b=}, {c=}")
        return f"captured {b=}, {c=}"


if __name__ == '__main__':
    from socketwrench import serve
    s = Sample()
    serve(s)
    # OR
    # serve(Sample)
    # OR
    # serve("socketwrench.samples.sample.Sample")