# socketwrench
A webserver based on `socket.socket` with no dependencies whatsoever other **socket** (or a substitute you pass in ) and **optional** standard library dependencies which improve features. See [dependencies](#dependencies) for more info.
Provides a lightweight quickstart to make an API which supports OpenAPI, Swagger, and more.

## NOTE:
this is **not** a production-ready web server. It is a learning tool and a lightweight way to make a simple API. While I attempted to reduce overhead in calls, I haven't taken time to thoroughly optimize, and I have not implemented any complex features to deal with security, performance, or scalability.

## Project Goals
Part of the goal of this project was to understand how web servers work and to make a simple web server that is easy to use and understand.
As learning progressed, features were added, but the code became a bit more complex.
To learn more about the basics of web servers and how to develop one from scratch, see [learning.md](./learning.md) or jump straight into the 
building blocks of source code in [simplestsocketwrench.py](./src/simplestsocketwrench.py) => [simplesocketwrench.py](./src/simplesocketwrench.py) => [socketwrench](./src/socketwrench).
If you would prefer to use this library, read on!

# Quickstart
### Install
```bash
pip install socketwrench
```

### Serve a class
```python
from socketwrench import serve, StaticFileHandler

class MyServer:
    src = StaticFileHandler(Path(__file__).parent.parent.parent)
    
    def hello(self):
        return "world"
  
if __name__ == '__main__':
    serve(MyServer, thread=True)
    # OR
    # m = MyServer()
    # serve(m)
    # OR
    # serve("my_module.MyServer")
```
* Go to http://localhost:8080/hello and see the response "world".
* Now go to http://localhost:8080/swagger to see the Swagger UI.
* OR go to http://localhost:8080/api to see a custom api playground.

# Features
## OpenAPI & Swagger
* Go to http://localhost:8080/swagger (after running `serve`) to see the Swagger UI.
* Go to http://localhost:8080/openapi.json  (after running `serve`) to see the autogenerated OpenAPI spec which Swagger uses. 


## Autofilled Parameters
Any of the following parameter names or typehints will get autofilled with the corresponding request data:
```python
available_types = {
    "request": Request, # full request object, contains all the other components
    "query": Query, # query string
    "body": Body, # request body bytes
    "headers": Headers, # request headers dict[str, str]
    "route": Route, # route string (without query string)
    "full_path": FullPath, # full path string (with query string)
    "method": Method, # request method str (GET, POST, etc.)
    "file": File, # file bytes (essentially the same as body)
    "client_addr": ClientAddr, # client ip address string (also contains host and port attributes)
    "socket": socket.socket, # the socket object for the client
}
```

### Decorators
```python
from socketwrench import route, methods, get, post, put, patch, delete, private
```
These decorators **do not modify** the functions they decorate, they simply `tag` the function by adding attributes to the functions.
```func.__dict__[key] = value```. This allows the setting function-specific preferences such as which methods to allow.
#### @tag
simply modifies the function's `__dict__` to add the specified attributes.
```python
@tag(do_not_serve=False, methods=["GET", "POST"], error_mode="traceback")
def my_function():
    pass
```

The following decorators set the `available_methods` attribute of the function to the specified methods and tells the server to override its default behavior for the function.
* `@methods("GET", "POST", "DELETE")`: equivalent to `@tag(available_methods=["GET", "POST", "DELETE"])`
* `@get`, `@post`, `@put`, `@patch`, `@delete`, `@private`: self-explanatory

### Route Decorator
`@route("/a/{c}")` tells the server to use /a/{c} as the route for the function instead of using the function's name as it normally does. This also allows for capturing path parameters. 
```python
@get
@post
@route("/a/{c}", error_mode="traceback")
def a(self, b, c=5):
    print(f"calling a with {b=}, {c=}")
    return f"captured {b=}, {c=}"
```

### Error Modes
* `"hide"` or `ErrorModes.HIDE`: returns `b"Internal Server Error"` in the response body when an error occurs.
* `type` or `ErrorModes.TYPE`: returns the error type only in the response body when an error occurs.
* `"short"` or `ErrorModes.SHORT`: returns the python error message but no traceback in the response body when an error occurs.
* `"traceback"` or `ErrorModes.TRACEBACK` or `ErrorModes.LONG` or `ErrorModes.TB`: returns the full traceback in the response body when an error occurs.

To set the default error mode for all functions, use `set_default_error_mode`.
```python
from socketwrench import set_default_error_mode, ErrorModes

set_default_error_mode(ErrorModes.TRACEBACK) # equivalent to ErrorModes=ErorModes.TRACEBACK
```

### favicon.ico
No need to use our favicon! pass a `str | Path` `.ico` filepath to `favicon` argument to use your own favicon. Alternatively, tag `@route('/favicon.ico')` on a function returning the path.

### fallback handler
Add a custom function to handle any requests that don't match any other routes.

# Dependencies
Default behavior is to use the standard library only. However, if you do not have the full standard library, socketwrench _should_ still work.
This is a work in progress as I am attempting to support micropython, circuitpython, etc. but I have not tested on these environments yet.

### How it works:
* `socket.socket` is the only required dependency, BUT you can pass in a substitute socket object if you want.
* The following standard library modules are used, BUT if import fails for any of them we fall back on dump fake versions I made in [src/socketwrench/fake_imports](.src/socketwrench/fake_imports) which attempt to approximate the same functionality
```python
import socket

import builtins  # very niche case use for if a function is typehinted to accept a type, e.g. `def f(x: type):` and you pass in the type name via a string query e.g. `?x=int`
import inspect  # used often for getting function signatures, autofilling parameters, etc., spoof version uses `__annotations__` and `__defaults__` of functions
from sys import argv # only used in commandline mode
from argparse import ArgumentParser # only used in commandline mode
from tempfile import TemporaryFile # only used if you attempt to return a folder using a StaticFileHandler
from zipfile import ZipFile # only used if you attempt to return a folder using a StaticFileHandler
from functools import wraps, partial # used regularly but easily replaced
import dataclasses # only used if your python function returns a dataclass which we try to coerce to json
from datetime import datetime  # used for Last-Modified header of File responses
from pathlib import Path # used for file responses and static file serving, spoof version works okay
from json import dumps, loads # used for json responses, spoof version works okay
import logging # used for logging, spoof version works okay
from time import sleep # only used if pause_sleep > 0 or accept_sleep > 0, spoof version does not sleep at all
from threading import Event, Thread # only used if you `thread=True` in `serve` function (defaults to False)
from traceback import format_exception  # only used if error_mode="traceback"
import importlib # only used if you pass a string into the serve module as the item to be served, e.g. in commandline mode
from sys import modules # only used if you pass a string into the serve module as the item to be served, e.g. in commandline mode
```

### sample
```python
from socketwrench import serve
import socket

class Sample:
    def hello(self):
        return "world"

if __name__ == '__main__':
    serve(Sample, spoof_modules="all", thread=True, socket=socket, port=8123)
```

# Planned Features
* [x] Implement nesting / recursion to serve deeper routes and/or multiple classes
* [x] support default navigation pages to help show links to available routes
* [ ] Enforce OpenAPI spec with better error responses
* [x] Serve static folders
* [x] Make a better playground for testing endpoints
  * [ ] better preview of variadic routes
* [ ] improve docs
  * [ ] document variadic routes
  * [ ] document autofilled parameters
  * [ ] document decorators
  * [ ] document error modes
  * [ ] document static file serving
  * [ ] document favicon
  * [ ] document fallback handler
  * [ ] document regexp / match routes
* [ ] Make a client-side python proxy object to make API requests from python

### Environment Support
* [x] Remove `|` typehints to allow for older python versions :/ (this makes me sad)
* [x] Remove standard library dependencies which microcontrollers may not have
* [x] Allow passing in a socket object
  * [ ] test and support different kinds of sockets and objects pretending to be sockets
* [ ] Test on ESP32 and other microcontrollers
* [ ] Test in browser-based python environments using pyodide

### Other
* [ ] Ideas? Let me know!

# Other Usage Modes
### Serve a module
Using commandline, just specify a filepath or file import path to a module.
```python
# my_module.py
def hello():
    return "world"
```
```commandline
python -m socketwrench my_module
```
NOTE: this mode is experimental and less tested than the other modes.

### Serve a single function on all routes
```python
from socketwrench import serve

def print_request(request):
    s = "<h>You made the following request:</h><br/>"
    s += f"<b>Method:</b> {request.method}<br/>"
    s += f"<b>Route:</b> {request.path.route()}<br/>"
    s += f"<b>Headers:</b><br/> {str(request.headers).replace('\n', '<br>')}<br/>"
    s += f"<b>Query:</b> {request.path.query_args()}<br/>"
    s += f"<b>Body:</b> {request.body}<br/>"
    return s


if __name__ == '__main__':
    serve(print_request)
```



## (mostly) Full Feature Sample
```python
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
```