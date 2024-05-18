
def format_exception(t, e, tb):
    return [f"{t.__name__}: {e}"] + (tb if isinstance(tb, list) else [])