def methods(*method):
    def decorator(handler):
        handler.__dict__["allowed_methods"] = method
        return handler
    return decorator


def private(handler):
    handler.__dict__["do_not_serve"] = True
    return handler


def get(handler):
    handler.__dict__["allowed_methods"] = ("GET",)
    return handler


def post(handler):
    handler.__dict__["allowed_methods"] = ("POST",)
    return handler


def put(handler):
    handler.__dict__["allowed_methods"] = ("PUT",)
    return handler


def patch(handler):
    handler.__dict__["allowed_methods"] = ("PATCH",)
    return handler


def delete(handler):
    handler.__dict__["allowed_methods"] = ("DELETE",)
    return handler

