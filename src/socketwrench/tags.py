from socketwrench.standardlib_dependencies import partial


def tag(handler=None, **kwargs):
    if handler is None:
        return partial(tag, **kwargs)

    for key, value in kwargs.items():
        handler.__dict__[key] = value
    return handler


def gettag(handler, tag_name, default=None):
    if hasattr(handler, "__dict__") and tag_name in handler.__dict__:
        return handler.__dict__[tag_name]
    return default


def methods(*methods):
    return partial(tag, allowed_methods=methods)


def private(handler):
    tag(handler, do_not_serve=True)
    return handler


def allowed_methods(*methods: str, autofill=None):
    def decorator(handler, route: str = None, error_mode: str = None, openapi: dict = None, autofill=None, allowed_methods=None, **kwargs):
        if allowed_methods is None:
            allowed_methods = methods
        if autofill is not None:
            kwargs["autofill"] = autofill
        if isinstance(handler, str) and route is None:
            return partial(decorator, route=handler, error_mode=error_mode, openapi=openapi, allowed_methods=allowed_methods, **kwargs)
        if route is not None:
            if "routes" not in handler.__dict__:
                tag(handler, routes=[], **kwargs)
            tag(handler, routes=list(set(handler.__dict__["routes"] + [route])), **kwargs)
        if allowed_methods is not None:
            if "allowed_methods" not in handler.__dict__:
                tag(handler, allowed_methods=[], **kwargs)
            tag(handler, allowed_methods=list(set(handler.__dict__["allowed_methods"] + list(allowed_methods))), **kwargs)
        if error_mode is not None:
            tag(handler, error_mode=error_mode, openapi=openapi, **kwargs)
        return handler
    return decorator


get = allowed_methods("GET")
post = allowed_methods("POST")
put = allowed_methods("PUT")
patch = allowed_methods("PATCH")
delete = allowed_methods("DELETE")
route = allowed_methods("GET", "POST", "PUT", "PATCH", "DELETE")

