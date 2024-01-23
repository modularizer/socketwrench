import inspect
import json
import builtins
import logging

from socketwrench.types import Request, Response, Query, Body, Route, FullPath, Method, File, ClientAddr, \
    HTTPStatusCode, ErrorResponse, Headers

logger = logging.getLogger("socketwrench")


class Autofill:
    def request(self, request: Request) -> Request:
        return request

    def query(self, request: Request) -> Query:
        return Query(request.path.query_args())

    def body(self, request: Request) -> Body:
        return request.body

    def headers(self, request: Request) -> Headers:
        return Headers(request.headers)

    def route(self, request: Request) -> Route:
        return Route(request.path.route())

    def full_path(self, request: Request) -> FullPath:
        return FullPath(request.path)

    def method(self, request: Request) -> Method:
        return Method(request.method)

    def file(self, request: Request) -> File:
        return File(request.body)

    def client_addr(self, request: Request) -> ClientAddr:
        return ClientAddr(request.client_addr)

    def autofill(self, special_params: dict):
        def f(request) -> dict:
            d = {}
            for k, values in special_params.items():
                v = getattr(self, k)(request)
                for _k in values:
                    d[_k] = v
            return d
        return f


available_types = {
    "request": Request,
    "query": Query,
    "body": Body,
    "headers": Headers,
    "route": Route,
    "full_path": FullPath,
    "method": Method,
    "file": File,
    "client_addr": ClientAddr,
}


def cast_to_typehint(value: str, typehint = inspect._empty):

    # unless specifically typed as a string, cast any numeric value to int or float
    if typehint is not str:
        # limited we can do here, but in general if a string is numeric it is far more likely it
        # should be an int or float than a string
        if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
            if typehint is float:
                return float(value)
            return int(value)
        # if it's a float, it will have a decimal point
        if "." in value:
            v = value.replace(".", "")
            if v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
                return float(value)
    if typehint in [str, inspect._empty]:
        return value
    if typehint in [int, float]:
        return typehint(value)
    if typehint is bool:
        return value.lower() in ("true", "t", "1")
    if typehint is list:
        try:
            return json.loads(value)
        except:
            if value.startswith("[") and value.endswith("]"):
                value = value[1:-1]
            elif value.startswith("(") and value.endswith(")"):
                value = value[1:-1]
            elif value.startswith("{") and value.endswith("}"):
                value = value[1:-1]
            values = value.split(",")
            values = [v.strip().strip('"') for v in values]
            return [cast_to_typehint(v) for v in values]
    if typehint in [tuple, set, frozenset]:
        return typehint(cast_to_typehint(value, list))
    if typehint is dict:
        return json.loads(value)
    if typehint is bytes:
        return value.encode()
    if typehint is bytearray:
        return bytearray(value.encode())
    if typehint is memoryview:
        return memoryview(value.encode())
    if typehint is type:
        if hasattr(builtins, value):
            return getattr(builtins, value)
        return globals().get(value, value)
    if hasattr(typehint, "__origin__"):
        if typehint.__origin__ in [list, tuple, set, frozenset]:
            return typehint([cast_to_typehint(v, typehint.__args__[0]) for v in value])
        return cast_to_typehint(value, typehint.__origin__)
    if hasattr(typehint, "__args__"):
        for t in typehint.__args__:
            try:
                return cast_to_typehint(value, t)
            except:
                pass
    return value


def cast_to_types(query, signature):
    for param_name, param_value in query.items():
        if param_name in signature:
            typehint = signature[param_name].annotation
            try:
                query[param_name] = cast_to_typehint(param_value, typehint)
            except:
                pass
    return query


def preprocess_args(_handler):
    import inspect
    sig = inspect.signature(_handler)

    # make sure the handler doesn't use "args" unless as *args
    if "args" in sig.parameters and sig.parameters["args"].kind != inspect.Parameter.VAR_POSITIONAL:
        raise ValueError("The handler cannot use 'args' as a parameter unless as *args.")

    # make sure the handler doesn't use "kwargs" unless as **kwargs
    if "kwargs" in sig.parameters and sig.parameters["kwargs"].kind != inspect.Parameter.VAR_KEYWORD:
        raise ValueError("The handler cannot use 'kwargs' as a parameter unless as **kwargs.")

    autofill = Autofill()

    # we will pass the request to any parameter named "request" or typed as Request
    special_params = {k: [] for k in available_types}

    available_type_values = list(available_types.values())
    available_type_keys = list(available_types.keys())
    ind = -1
    args_before_collector = 0
    collector_found = False
    for name, param in sig.parameters.items():
        ind += 1

        if param.annotation in available_type_values:
            i = available_type_values.index(param.annotation)
            key = available_type_keys[i]
            special_params[key].append(name)
        elif param.annotation is inspect._empty and param.name in available_types:
            special_params[param.name].append(name)
        elif param.name in available_types and not issubclass(param.annotation, available_types[param.name]):
            raise ValueError(f"Parameter '{param.name}' must be typed as {available_types[param.name]}.")

        if collector_found:
            pass
        elif param.kind == inspect.Parameter.VAR_POSITIONAL:
            collector_found = True
        elif param.kind == inspect.Parameter.VAR_KEYWORD:
            collector_found = True
        else:
            args_before_collector += 1


    get_autofill_kwargs = autofill.autofill(special_params)


    def parser(request: Request) -> tuple[tuple, dict, type]:
        if not sig.parameters:
            return (), {}, sig.return_annotation
        args = []
        kwargs = get_autofill_kwargs(request)
        q = request.path.query_args()
        if q:
            int_keys = sorted([int(k) for k in q if k.isdigit()])
            if set(int_keys) != set(range(len(int_keys))):
                raise ValueError("Unable to parse args.")

            for k in int_keys:
                v = q.pop(str(k))
                if k < args_before_collector:
                    param_name = list(sig.parameters)[k]
                    try:
                        v = cast_to_typehint(v, sig.parameters[param_name].annotation)
                    except:
                        pass
                args.append(v)
            q = cast_to_types(q, sig.parameters)
            kwargs.update(q)

        b = request.body
        if b:
            try:
                body = json.loads(b.decode())
                int_keys = sorted([int(k) for k in body if k.isdigit()])
                if set(int_keys) != set(range(len(args), len(args) + len(int_keys))):
                    raise ValueError("Unable to parse args.")
                for k in int_keys:
                    args.append(body.pop(str(k)))
                kwargs.update(body)
            except:
                pass

        if "args" in kwargs:
            args = tuple(kwargs.pop("args"))
        else:
            args = tuple(args)
        return args, kwargs, sig.return_annotation
    return parser


def wrap_handler(_handler):
    """Converts any method into a method that takes a Request and returns a Response."""
    if getattr(_handler, "is_wrapped", False):
        return _handler
    parser = preprocess_args(_handler)

    def wrapper(request: Request) -> Response:
        try:
            if parser is None:
                r = _handler()
                response = Response(r, version=request.version)
            else:
                a, kw, return_annotation = parser(request)
                r = _handler(*a, **kw)
                if isinstance(r, HTTPStatusCode):
                    response = Response(r.phrase(), status_code=r, version=request.version)
                else:
                    try:
                        if issubclass(return_annotation, Response):
                            response = return_annotation(r)
                        else:
                            response = Response(r, version=request.version)
                    except:
                        response = Response(r, version=request.version)
        except Exception as e:
            logger.exception(e)
            response = ErrorResponse(b'Internal Server Error', version=request.version)
        return response

    wrapper.__dict__["is_wrapped"] = True
    return wrapper


class RouteHandler:
    def __init__(self,
                 routes: dict | None = None,
                 fallback_handler=None,
                 base_path: str = "/",
                 require_tag: bool = False
                 ):
        self.base_path = base_path
        self.require_tag = require_tag

        self.routes = routes if isinstance(routes, dict) else {}
        if routes and not isinstance(routes, dict):
            self.parse_routes_from_object(routes)
        self.fallback_handler = wrap_handler(fallback_handler) if fallback_handler else None

    def parse_routes_from_object(self, obj):
        for k in dir(obj):
            if not k.startswith("_"):
                v = getattr(obj, k)
                if callable(v):
                    if self.require_tag and not hasattr(v, "allowed_methods"):
                        continue
                    if getattr(v, "do_not_serve", False):
                        continue
                    self[k] = v

    def __call__(self, request: Request) -> Response:
        handler = self.routes.get(request.path.route(), self.fallback_handler)
        allowed_methods = getattr(handler, "allowed_methods", None)
        if request.method == "HEAD" and "GET" in allowed_methods:
            allowed_methods = list(allowed_methods) + ["HEAD"]
        if allowed_methods is None or request.method not in allowed_methods:
            return Response(b'Method Not Allowed',
                            status_code=405,
                            headers={"Content-Type": "text/plain"},
                            version=request.version)
        if handler is None:
            # send a response with 404
            return Response(b'Not Found',
                            status_code=404,
                            headers={"Content-Type": "text/plain"},
                            version=request.version)
        r = handler(request)
        return r

    def route(self, handler, route: str | None = None, allowed_methods: tuple[str] | None = None):
        if isinstance(handler, str):
            return lambda handler: self.route(handler, route, allowed_methods)

        if route is None:
            route = handler.__name__
        if allowed_methods is None:
            allowed_methods = getattr(handler, "allowed_methods", ("GET",))
        h = wrap_handler(handler)
        h.__dict__["allowed_methods"] = allowed_methods
        self.routes[self.base_path + route] = h

    def get(self, handler=None, route: str | None = None):
        return self.route(handler, route, allowed_methods=("GET",))

    def post(self, handler=None, route: str | None = None):
        return self.route(handler, route, allowed_methods=("POST",))

    def put(self, handler=None, route: str | None = None):
        return self.route(handler, route, allowed_methods=("PUT",))

    def patch(self, handler=None, route: str | None = None):
        return self.route(handler, route, allowed_methods=("PATCH",))

    def delete(self, handler=None, route: str | None = None):
        return self.route(handler, route, allowed_methods=("DELETE",))

    def head(self, handler=None, route: str | None = None):
        route = route or handler.__name__

        def wrapper(request: Request) -> Response:
            response = handler(request)
            response.body = b""
            return response

        return self.route(wrapper, route, allowed_methods=("HEAD",))

    def __getitem__(self, item):
        return self.routes[self.base_path + item]

    def __setitem__(self, key, value):
        self.route(value, key)

    def __getattr__(self, item):
        return self.__class__(self.fallback_handler, self.routes, self.base_path + item + "/")
