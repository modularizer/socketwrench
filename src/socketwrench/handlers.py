from socketwrench.standardlib_dependencies import (
    builtins,
    inspect,
    loads,
    logging,
    Path,
    socket,
    wraps
)

from socketwrench.tags import tag, get, gettag
from socketwrench.types import Request, Response, Query, Body, Route, FullPath, Method, File, ClientAddr, \
    HTTPStatusCode, ErrorResponse, Headers, ErrorModes, FileResponse, url_decode, StandardHTMLResponse

logger = logging.getLogger("socketwrench")


class Autofill:
    def request(self, request: Request) -> Request:
        return request

    def socket(self, request: Request) -> socket.socket:
        return request.connection_socket

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
    "socket": socket.socket,
}

def tryissubclass(a, others):
    try:
        if isinstance(others, type):
            return issubclass(a, others)
    except:
        pass
    for o in others:
        try:
            if issubclass(a, o):
                return True
        except:
            pass
    return False

def _typehint_matches(typehint, others):
    return typehint in others or tryissubclass(typehint, others) or (hasattr(typehint, "__origin__") and typehint.__origin__ in others) or (hasattr(typehint, "__args__") and any(_typehint_matches(t, others) for t in typehint.__args__))


def cast_to_typehint(value: str, typehint = inspect.Parameter.empty):

    # unless specifically typed as a string, cast any numeric value to int or float
    if _typehint_matches(typehint, [int, inspect.Parameter.empty]):
        if value.isdigit() or (value.startswith("-") and value[1:].isdigit())  and not '.' in value:
            return int(value)
    if _typehint_matches(typehint, [float, inspect.Parameter.empty]):
        if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
            return float(value)
    if _typehint_matches(typehint, [bool, inspect.Parameter.empty]):
        if value.lower() in ["false", "f", "no", "n"]:
            return False
        if value.lower() in ["true", "t", "yes", "y"]:
            return True
    if value.lower() in ["none", "null"] and (_typehint_matches(typehint, [None]) or not _typehint_matches(typehint, [str])):
        return None
    if _typehint_matches(typehint, [bool]):
        if value.lower() in ["0"]:
            return False
        if value.lower() in ["1", "ok"]:
            return True
    if _typehint_matches(typehint, [list, inspect.Parameter.empty]):
        if value.startswith("[") and value.endswith("]"):
            try:
                return loads(value)
            except:
                pass
    if _typehint_matches(typehint, [tuple, inspect.Parameter.empty]):
        if value.startswith("(") and value.endswith(")"):
            try:
                s = '[' + value[1:-1] + ']'
                return tuple(loads(s))
            except:
                pass
    if _typehint_matches(typehint, [dict, inspect.Parameter.empty]):
        if value.startswith("{") and value.endswith("}"):
            try:
                return loads(value)
            except:
                pass
    if _typehint_matches(typehint, [frozenset]):
        if value.startswith("{") and value.endswith("}"):
            try:
                return frozenset(loads('[' + value[1:-1] + ']'))
            except:
                pass
    if _typehint_matches(typehint, [set, inspect.Parameter.empty]):
        if value.startswith("{") and value.endswith("}"):
            try:
                return set(loads('[' + value[1:-1] + ']'))
            except:
                pass
    if typehint is bytes or tryissubclass(typehint, bytes):
        return value.encode()
    if typehint is bytearray or tryissubclass(typehint, bytearray):
        return bytearray(value.encode())
    if typehint is memoryview or tryissubclass(typehint, memoryview):
        return memoryview(value.encode())
    if typehint is type:
        if builtins and hasattr(builtins, value):
            return getattr(builtins, value)
        return globals().get(value, value)
    if hasattr(typehint, "__origin__"):
        if typehint.__origin__ in [list, tuple, set, frozenset]:
            return typehint([cast_to_typehint(v, typehint.__args__[0]) for v in value])
        return cast_to_typehint(value, typehint.__origin__)
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
        elif param.annotation is inspect.Parameter.empty and param.name in available_types:
            special_params[param.name].append(name)
        elif param.name in available_types:
            a = param.annotation
            t = available_types[param.name]
            if isinstance(a, str):
                if a != t.__name__ and a not in [_t.__name__ for _t in t.__subclasses()]:
                    raise ValueError(f"Parameter '{param.name}' of {_handler} must be typed as {available_types[param.name]}, not {param.annotation}.")
            elif not a is t or issubclass(a, t):
                raise ValueError(f"Parameter '{param.name}' of {_handler} must be typed as {available_types[param.name]}, not {param.annotation}.")

        if collector_found:
            pass
        elif param.kind == inspect.Parameter.VAR_POSITIONAL:
            collector_found = True
        elif param.kind == inspect.Parameter.VAR_KEYWORD:
            collector_found = True
        else:
            args_before_collector += 1


    get_autofill_kwargs = autofill.autofill(special_params)

    def parser(request: Request, route_params: dict = None) -> tuple[tuple, dict, type]:
        route_params = cast_to_types(route_params, sig.parameters) if route_params else {}
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
                body = loads(b.decode())
                int_keys = sorted([int(k) for k in body if k.isdigit()])
                if set(int_keys) != set(range(len(args), len(args) + len(int_keys))):
                    raise ValueError("Unable to parse args.")
                for k in int_keys:
                    args.append(body.pop(str(k)))
                kwargs.update(body)
            except:
                pass

        kwargs.update(route_params)

        if "args" in kwargs:
            args = tuple(kwargs.pop("args"))
        else:
            args = tuple(args)
        return args, kwargs, sig.return_annotation

    tag(parser, autofill=special_params, sig=sig)
    return parser

@tag(accepts_route_params=True)
def wrap_handler(_handler, error_mode: str = None):
    """Converts any method into a method that takes a Request and returns a Response."""
    if getattr(_handler, "is_wrapped", False):
        return _handler
    parser = preprocess_args(_handler)


    # make a stub function that takes the same parameters as the handler but doesn't do anything
    # use inspect.signature to get the parameters

    @wraps(_handler)
    def wrapper(request: Request, route_params: dict = None) -> Response:
        try:
            if parser is None:
                r = _handler()
                response = Response(r, version=request.version)
            else:
                a, kw, return_annotation = parser(request, route_params=route_params)
                r = _handler(*a, **kw)
                if isinstance(r, Response):
                    response = r
                elif isinstance(r, HTTPStatusCode):
                    response = Response(r.phrase(), status_code=r, version=request.version)
                else:
                    try:
                        if (not isinstance(return_annotation, str)) and issubclass(return_annotation, Response):
                            response = return_annotation(r)
                        else:
                            response = Response(r, version=request.version)
                    except:
                        response = Response(r, version=request.version)
        except Exception as e:
            logger.exception(e)
            _error_mode = error_mode if error_mode is not None else ErrorModes.DEFAULT
            if _error_mode == ErrorModes.HIDE:
                msg = b'Internal Server Error'
            elif _error_mode == ErrorModes.TYPE:
                msg = str(type(e)).encode()
            elif _error_mode == ErrorModes.SHORT:
                msg = str(e).encode()
            elif _error_mode == ErrorModes.LONG:
                from socketwrench.standardlib_dependencies import format_exception
                msg = "".join(format_exception(type(e), e, e.__traceback__)).encode()
            response = ErrorResponse(msg, version=request.version)
        return response

    tag(wrapper,
        is_wrapped=True,
        sig=getattr(parser, "sig", inspect.signature(_handler)),
        autofill=getattr(parser, "autofill", {}), **_handler.__dict__)

    if hasattr(_handler, "match"):
        tag(wrapper, match=_handler.match)
    return wrapper


class MatchableHandlerABC:
    def match(self, route: str) -> bool:
        raise NotImplementedError

    def __call__(self, request: Request) -> Response:
        raise NotImplementedError


class StaticFileHandler(MatchableHandlerABC):
    is_wrapped = True
    allowed_methods = ["GET", "HEAD"]

    def __init__(self, path, route: str = None):
        self.path = path
        self.route = route or "/" + path.name
        self.allowed_methods = ["GET", "HEAD"]

    def match(self, route: str) -> bool:
        if not route.startswith(self.route):
            return False
        added = route[len(self.route):]
        p = (self.path / added.strip("/")) if added else self.path
        if not p.exists():
            return False
        return True

    def __call__(self, request: Request) -> Response:
        route = request.path.route()
        if not route.startswith(self.route):
            return Response(b"Not Found", status_code=404, version=request.version)
        added = route[len(self.route):]
        p = (self.path / added.strip("/")) if added else self.path

        if p.is_dir() and (p / "index.html").exists():
            p = p / "index.html"
        if not p.exists():
            return Response(b"Not Found", status_code=404, version=request.version)
        elif p.is_dir():
            folder_contents = list(p.iterdir())
            contents = "<!DOCTYPE html><html><body><ul>" + "\n".join([f"<li><a href='{route}/{f.name}'>{f.name}</a></li>" for f in folder_contents]) + "</ul></body></html>"
            return Response(contents.encode(), version=request.version)
        r = FileResponse(p, version=request.version)
        return r


def matches_variadic_route(route: str, variadic_route: str) -> dict:
    try:
        if route.endswith("/") and not variadic_route.endswith("/"):
            route = route[:-1]
        elif variadic_route.endswith("/") and not route.endswith("/"):
            variadic_route = variadic_route[:-1]
        route_parts = route.split("/")
        variadic_parts = variadic_route.split("/")
        n = len(route_parts)
        if n != len(variadic_parts):
            return False

        found_matches = {}
        identical_characters = 0
        for i in range(n):
            r = route_parts[i]
            v = variadic_parts[i]
            if r == v:
                identical_characters += len(r)
            else:
                if not ('{' in v and '}' in v):
                    return False
                sections = []
                current_section = {}
                for c in v:
                    if c == "{":
                        if current_section.get("variadic", False):
                            return False
                        sections.append(current_section)
                        current_section = {"variadic": True, "value": ""}
                    elif c == "}":
                        if not current_section.get("variadic", True):
                            return False
                        sections.append(current_section)
                        current_section = {"variadic": False, "value": ""}
                    else:
                        if not current_section:
                            current_section = {"variadic": False, "value": ""}
                        current_section["value"] += c
                sections.append(current_section)
                sections = [s for s in sections if s]
                sections = [s for s in sections if s["value"]]
                if len(sections) == 1 and not sections[0]["variadic"]:
                    found_matches[sections[0]["value"]] = r
                    continue
                # make sure they alternate
                if not all([s["variadic"] != sections[i + 1]["variadic"] for i, s in enumerate(sections[:-1])]):
                    raise ValueError("Variadic sections must alternate")

                if any(s["value"] in found_matches and s["variadic"] for s in sections):
                    raise ValueError("Variadic sections must be unique")

                nonvariadic_start = 0
                nonvariadic_end = 0
                variadic_name = None
                variables = {}
                for section in sections:
                    if section["variadic"]:
                        variadic_name = section["value"]
                        continue
                    else:
                        if section["value"] not in r[nonvariadic_end:]:
                            return False
                        identical_characters += len(section["value"])
                        i = r[nonvariadic_end:].index(section["value"])
                        nonvariadic_start = nonvariadic_end + i
                        if variadic_name:
                            variables[variadic_name] = r[nonvariadic_end:nonvariadic_start]

                        nonvariadic_end = nonvariadic_start + len(section["value"])

                        nv = r[nonvariadic_start:nonvariadic_end]
                        if nv != section["value"]:
                            raise ValueError(f"Expected {section['value']} but got {nv}")
                        nonvariadic_start = nonvariadic_end
                if sections[-1]["variadic"]:
                    variables[variadic_name] = r[nonvariadic_end:]
                elif nonvariadic_end < len(r):
                    return False
                found_matches.update(variables)


        return found_matches
    except Exception as e:
        return False


def sort_variadic_routes(patterns):
    q = []
    for pattern in patterns:
        parts = pattern.split("/")
        part_count = len(parts)
        variadic_part_count = len([p for p in parts if "{" in p and "}" in p])
        nonvariadic_part_count = part_count - variadic_part_count
        total_variadic_pattern_count = sum([1 * (c=='{') for c in pattern])
        total_nonvariadic_chars = 0
        in_variadic = False
        for c in pattern:
            if c == "{":
                in_variadic = True
            elif c == "}":
                in_variadic = False
            elif not in_variadic:
                total_nonvariadic_chars += 1
        q.append((part_count,
                  nonvariadic_part_count,
                  total_nonvariadic_chars,
                  total_variadic_pattern_count,
                  len(pattern),
                  pattern))
    sorted_patterns = [_v[-1] for _v in reversed(sorted(q))]
    return sorted_patterns


def is_object_instance(obj):
    # Check if obj is an instance of a custom class
    if not hasattr(obj, '__class__'):
        return False
    # Get all members of the object's class
    members = inspect.getmembers(obj.__class__, predicate=inspect.isfunction)

    # Check if there are any user-defined methods (excluding special methods)
    user_defined_methods = [name for name, f in members if not name.startswith('_')]

    return bool(user_defined_methods)


class RouteHandler:
    resources_folder = Path(__file__).parent / "resources"
    playground_folder = resources_folder / "playground"
    default_favicon = resources_folder / "favicon.ico"

    def __init__(self,
                 routes: dict = None,
                 fallback_handler=None,
                 base_path: str = "/",
                 require_tag: bool = False,
                 error_mode: str = ErrorModes.HIDE,
                 favicon: str = default_favicon,
                 nav_path = "/",
                 nav_recursion = True,
                 ):
        base_path = base_path.replace("//", "/")
        if not base_path.endswith("/"):
            base_path += "/"
        self.base_path = base_path
        self.require_tag = require_tag
        self.error_mode = error_mode
        self.favicon_path = favicon

        self.routes = {}
        self.matchable_routes = {}
        self.variadic_routes = {}
        self.sub_route_handlers = {}
        self.nav_path = nav_path
        self.nav_recursion = nav_recursion
        if routes:
            if isinstance(routes, type):
                routes = routes()

            kw = {
                "error_mode": error_mode,
                "require_tag": require_tag,
                "nav_path": nav_path,
                "nav_recursion": nav_recursion,
            }
            if isinstance(routes, dict):
                for k, v in routes.items():
                    sub = self.base_path + (k[1:] if k.startswith("/") else k) + "/"
                    sub = sub.replace("//", "/")

                    if isinstance(v, type):
                        self._add_subroute(sub, RouteHandler(v(), **kw))
                    elif isinstance(v, RouteHandler):
                        self._add_subroute(sub, v)
                    elif isinstance(v, dict):
                        self._add_subroute(sub, RouteHandler(v, base_path=sub, **kw))
                    elif is_object_instance(v):
                        self._add_subroute(sub, RouteHandler(v, base_path=sub, **kw))
                    else:
                        self[k] = v
            else:
                self.parse_routes_from_object(routes)
        self.fallback_handler = wrap_handler(fallback_handler) if fallback_handler else None

        op = wrap_handler(self.openapi, error_mode=error_mode)
        sw = wrap_handler(self.swagger, error_mode=error_mode)

        self.default_routes = {
            "/api-docs": op,
            "/openapi.json": op,
            "/swagger": sw,
            "/docs": sw,
            "/swagger-ui": sw,
            "/api": wrap_handler(self.playground, error_mode=error_mode),
            "/api/playground.js": wrap_handler(self.playground_js, error_mode=error_mode),
            "/api/panels.js": wrap_handler(self.playground_panels_js, error_mode=error_mode),
        }
        if self.favicon_path:
            self.default_routes["/favicon.ico"] = wrap_handler(self.favicon, error_mode=error_mode)

    def _add_subroute(self, sub, handler):
        if sub in self.sub_route_handlers:
            raise NotImplementedError(f"Route {sub} already exists. Duplicate routes are not allowed.")
        self.sub_route_handlers[sub] = handler

    def _all_routes(self, recursive=True):
        d = {
            **self.routes,
            **self.variadic_routes
        }
        if recursive:
            for k, v in self.sub_route_handlers.items():
                d.update(v._all_routes(recursive))
        return d
    @get
    def openapi(self) -> str:
        from socketwrench.openapi import openapi_schema
        d = self._all_routes()
        o = openapi_schema(d)
        return o

    @get
    def favicon(self, request: Request) -> Response:
        try:
            r = FileResponse(self.favicon_path, version=request.version)
        except Exception as e:
            r = Response(b"Not Found", status_code=404, version=request.version)
        return r

    @get
    def swagger(self) -> FileResponse:
        return FileResponse(Path(__file__).parent / "resources" / "swagger.html")

    @get
    def playground(self) -> Path:
        return self.playground_folder / "playground.html"

    @get
    def playground_js(self) -> Path:
        return self.playground_folder /  "playground.js"

    @get
    def playground_panels_js(self) -> Path:
        return self.playground_folder / "panels.js"

    def parse_routes_from_object(self, obj):
        for k in dir(obj):
            if not k.startswith("_"):
                v = getattr(obj, k)
                if callable(v):
                    if self.require_tag and not hasattr(v, "allowed_methods"):
                        continue
                    if getattr(v, "do_not_serve", False):
                        continue
                    routes = getattr(v, "routes", [k])
                    for route in routes:
                        try:
                            self[route] = v
                        except:
                            pass
        if callable(obj):
            self[""] = obj

    def get_nav(self, start=""):
        routes = self._all_routes(self.nav_recursion)
        links = []
        for route in routes:
            if route.startswith(start):
                r = route[len(start):]
                if r.startswith("/"):
                    r = r[1:]
                links.append((f"./{r}", route))
        links = sorted(links)
        nav = "<ul>\n" + "\n\t".join([f'<li><a href="{rel}">{full}</a></li>' if '{' not in full else f'<li>{full}</li>' for rel, full in links]) + "\n</ul>"
        return StandardHTMLResponse(nav, title=self.base_path)

    def __call__(self, request: Request) -> Response:
        route = request.path.route()

        if not route.startswith(self.base_path):
            return Response(b'Not Found',
                            status_code=404,
                            headers={"Content-Type": "text/plain"},
                            version=request.version)
        # search from longest to shortest subroute by length or string
        subroute_keys = sorted(self.sub_route_handlers.keys(), key=lambda x: (len(x), x), reverse=True)
        for k in subroute_keys:
            if route.startswith(k):
                return self.sub_route_handlers[k](request)

        handler = self.routes.get(route, None)

        route_params = {}
        if handler is None:
            for k, v in self.matchable_routes.items():
                if v.match(route):
                    handler = v
                    break
            else:
                if route in self.default_routes:
                    handler = self.default_routes[route]
                else:
                    x = url_decode(route)
                    if "{" in x and x in self.variadic_routes:
                        raise ValueError(f"Route {route} is variadic , {{}} patterns should be filled in")
                    # check all variadic routes in the correct order, first by number of parts, then number of variadic parts, then length of nonvariadic parts
                    variadic_patterns = sort_variadic_routes(list(self.variadic_routes.keys()))

                    for k in variadic_patterns:
                        # these are in format /a/{b}/c/{d}/e, convert to regexp groups
                        route_params = matches_variadic_route(route, k)
                        if route_params:
                            handler = self.variadic_routes[k]
                            for _k, _v in route_params.items():
                                if hasattr(handler, "__dict__") and _k in handler.__dict__:
                                    options = handler.__dict__[_k]
                                    if _v == options:
                                        # good! matches exactly
                                        continue
                                    elif isinstance(options, (list, tuple, set, frozenset)):
                                        for o in options:
                                            if str(o) == _v:
                                                # good! matches exactly one of the options
                                                break
                                            try:
                                                if isinstance(o, type):
                                                    if isinstance(_v, o):
                                                        # good! matches the type of one of the options
                                                        break
                                            except:
                                                pass
                                        else:
                                            # oops! didn't match any of the options
                                            break
                                        continue
                                    elif isinstance(options, type):
                                        try:
                                            options(_v)
                                            continue
                                        except:
                                            # oops! didn't match the type
                                            break
                                    else:
                                        # unable to interpret the options, maybe raise an error?
                                        continue
                            else:
                                # this means the route_params matched all the options, which means we found the right handler
                                break
                    else:
                        handler = self.fallback_handler

        if handler is None and route.endswith(self.nav_path):
            return self.get_nav(route[:-len(self.nav_path)])

        if handler is None:
            # send a response with 404
            return Response(b'Not Found',
                            status_code=404,
                            headers={"Content-Type": "text/plain"},
                            version=request.version)
        allowed_methods = gettag(handler, "allowed_methods", None)
        # if allowed_methods is None:
        #     print(handler, handler.__dict__)
        if request.method == "HEAD" and "GET" in allowed_methods:
            allowed_methods = list(allowed_methods) + ["HEAD"]
        if allowed_methods is None or request.method not in allowed_methods:
            return Response(b'Method Not Allowed',
                            status_code=405,
                            headers={"Content-Type": "text/plain"},
                            version=request.version)
        if route_params:
            r = handler(request, route_params)
        else:
            r = handler(request)
        return r

    # def route(self, handler, route: str | None = None, allowed_methods: tuple[str] | None = None):
    def route(self, handler, route = None, allowed_methods = None):
        route = route.replace("//", "/")
        if isinstance(handler, Path):
            handler = StaticFileHandler(Path, route)

        if isinstance(handler, str):
            return lambda handler: self.route(handler, route, allowed_methods)

        if route is None:
            route = handler.__name__
        if allowed_methods is None:
            allowed_methods = getattr(handler, "allowed_methods", ("GET",))
        em = getattr(handler, "error_mode", self.error_mode)
        h = wrap_handler(handler, error_mode=em)
        h.__dict__["allowed_methods"] = allowed_methods
        if self.base_path == "/" and route.startswith("/"):
            route = route[1:]

        sub = self.base_path + route + ("/" if not route.endswith("/") else "")
        sub = sub.replace("//", "/")
        if "{" in route and "}" in route:
            self.variadic_routes[sub] = h
        elif hasattr(h, "match") and callable(h.match):
            self.matchable_routes[sub] = h
        else:
            self.routes[sub] = h

    def get(self, handler=None, route: str = None):
        return self.route(handler, route, allowed_methods=("GET",))

    def post(self, handler=None, route: str = None):
        return self.route(handler, route, allowed_methods=("POST",))

    def put(self, handler=None, route: str = None):
        return self.route(handler, route, allowed_methods=("PUT",))

    def patch(self, handler=None, route: str = None):
        return self.route(handler, route, allowed_methods=("PATCH",))

    def delete(self, handler=None, route: str = None):
        return self.route(handler, route, allowed_methods=("DELETE",))

    def head(self, handler=None, route: str = None):
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


if __name__ == "__main__":
    items = ["23", "3.14", "True", "False", "1", "0", "[1, 2, 3]", "(1, 2, 3)", "{1, 2, 3}", "{1: 2, 3: 4}", "hello", "world"]
    d = {v: (cast_to_typehint(v), type(cast_to_typehint(v))) for v in items}
