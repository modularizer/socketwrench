def wraps(func):
    def wrapper(func2):
        try:
            func2.__dict__.update(func.__dict__)
        except:
            pass
        return func2

    return wrapper


def partial(func, *args, **kwargs):
    def wrapper(*args2, **kwargs2):
        return func(*args, *args2, **kwargs, **kwargs2)

    return wrapper