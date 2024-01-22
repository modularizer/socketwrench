import json

from socketwrench.types import Request, Response, Query, Body, Hash, Route, FullPath, Method, File, ClientAddr, \
    HTTPStatusCode, ErrorResponse, Headers


class Autofill:
    def request(self, request: Request) -> Request:
        return request

    def query(self, request: Request) -> Query:
        return Query(request.path.query_args())

    def body(self, request: Request) -> Body:
        return request.body

    def headers(self, request: Request) -> Headers:
        return Headers(request.headers)

    def hash(self, request: Request) -> Hash:
        return Hash(request.path.hash())

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

    def autofill(self, keys):
        def f(request) -> dict:
            return {k: getattr(self, k)(request) for k in keys}
        return f


available_types = {
    "request": Request,
    "query": Query,
    "body": Body,
    "hash": Hash,
    "headers": Headers,
    "route": Route,
    "full_path": FullPath,
    "method": Method,
    "file": File,
    "client_addr": ClientAddr,
}


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
    special_params = set({})
    for name, type in available_types.items():
        if name in sig.parameters:
            if sig.parameters[name].annotation != type:
                raise ValueError(f"The handler cannot use '{name}' as a parameter unless as {type}.")
            special_params.add(name)

    get_autofill_kwargs = autofill.autofill(special_params)


    def parser(request: Request) -> tuple[tuple, dict]:
        if not sig.parameters:
            return (), {}
        kwargs = get_autofill_kwargs(request)
        q = request.path.query_args()
        if q:
            kwargs.update(q)
        b = request.body
        if b:
            try:
                body = json.loads(b.decode())
                kwargs.update(body)
            except:
                pass

        if "args" in kwargs:
            args = kwargs.pop("args")
        else:
            args = {}
            for k in kwargs:
                if (isinstance(k, str) and k.isdigit()) or isinstance(k, int):
                    args[int(k)] = kwargs[k]
            if args and set(args.keys()) - set(range(len(args))):
                raise ValueError("Unable to parse args.")
            args = tuple(args[i] for i in range(len(args)))
        return args, kwargs
    return parser


def wrap_handler(_handler):
    parser = preprocess_args(_handler)
    def wrapper(request: Request) -> Response:
        try:
            a, kw = parser(request)
            r = _handler(*a, **kw)
            if isinstance(r, HTTPStatusCode):
                response = Response(r.phrase(), status_code=r, version=request.version)
            else:
                response = Response(r)

        except Exception as e:
            response = ErrorResponse(b'Internal Server Error', version=request.version)
        return response
    return wrapper


class RouteHandler:
    def __init__(self, routes: dict | None = None, fallback_handler=None, base_path: str = "/"):
        self.base_path = base_path

        self.routes = routes if isinstance(routes, dict) else {}
        if routes and not isinstance(routes, dict):
            self.parse_routes_from_object(routes)
        self.fallback_handler = fallback_handler

    def parse_routes_from_object(self, obj):
        for k in dir(obj):
            if not k.startswith("_"):
                v = getattr(obj, k)
                if callable(v):
                    self[k] = v

    def __call__(self, request: Request) -> Response:
        handler = self.routes.get(request.path.route(), self.fallback_handler)
        allowed_methods = getattr(handler, "allowed_methods", None)
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
